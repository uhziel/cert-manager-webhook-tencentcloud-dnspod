package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	apiextv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"

	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&customDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type customDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
	ctx    context.Context
	dnspod map[string]*dnspod.Client
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type customDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	SecretIdRef  cmmetav1.SecretKeySelector `json:"secretIdRef"`
	SecretKeyRef cmmetav1.SecretKeySelector `json:"secretKeyRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *customDNSProviderSolver) Name() string {
	return "dnspod"
}

func (c *customDNSProviderSolver) getDnspodClient(
	ch *v1alpha1.ChallengeRequest,
	cfgJSON *apiextv1.JSON,
) (*dnspod.Client, error) {
	cfg, err := loadConfig(cfgJSON)
	if err != nil {
		return nil, fmt.Errorf("getDnspodClient fail: %w", err)
	}

	secretId, err := loadSecretData(c.ctx, c.client, ch.ResourceNamespace, cfg.SecretIdRef)
	if err != nil {
		return nil, err
	}

	dnspodClient, ok := c.dnspod[secretId]
	if ok {
		return dnspodClient, nil
	}

	secretKey, err := loadSecretData(c.ctx, c.client, ch.ResourceNamespace, cfg.SecretKeyRef)
	if err != nil {
		return nil, err
	}

	credential := common.NewCredential(secretId, secretKey)
	dnspodClient, err = dnspod.NewClient(credential, "", profile.NewClientProfile())
	if err != nil {
		return nil, fmt.Errorf("create dnspod client fail: %w", err)
	}
	fmt.Println("create dnspod client successfully")
	c.dnspod[secretId] = dnspodClient

	return dnspodClient, nil
}

func loadSecretData(
	ctx context.Context,
	client *kubernetes.Clientset,
	namespace string,
	secretKeyRef cmmetav1.SecretKeySelector,
) (string, error) {
	secret, err := client.CoreV1().Secrets(namespace).Get(ctx, secretKeyRef.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("loadSecretData %v fail: %w", secretKeyRef, err)
	}

	v, ok := secret.Data[secretKeyRef.Key]
	if !ok {
		return "", fmt.Errorf("don't find SecretData namespace=%v secretKeyRef=%v", namespace, secretKeyRef)
	}

	return string(v), nil
}

func extractSubDomain(fqdn, zone string) string {
	if idx := strings.Index(fqdn, "."+zone); idx != -1 {
		return fqdn[:idx]
	}

	return util.UnFqdn(fqdn)
}

func findRecord(dnspodClient *dnspod.Client, domain, subDomain, recordType, value string) (*dnspod.RecordListItem, error) {
	req := dnspod.NewDescribeRecordListRequest()
	req.Domain = &domain
	req.Subdomain = &subDomain
	req.RecordType = &recordType

	resp, err := dnspodClient.DescribeRecordList(req)
	if err != nil {
		if err, ok := err.(*errors.TencentCloudSDKError); ok {
			if err.Code == "ResourceNotFound.NoDataOfRecord" {
				return nil, nil
			}
		}
		return nil, fmt.Errorf("find text record fail: %w", err)
	}

	for _, record := range resp.Response.RecordList {
		if *record.Value == value {
			return record, nil
		}
	}

	return nil, nil
}

func createTXTRecord(dnspodClient *dnspod.Client, domain, subDomain, value string) error {
	req := dnspod.NewCreateRecordRequest()
	req.Domain = &domain
	req.SubDomain = &subDomain
	req.Value = &value
	req.RecordType = common.StringPtr("TXT")
	req.RecordLine = common.StringPtr("默认")

	_, err := dnspodClient.CreateRecord(req)
	if err == nil {
		fmt.Printf("created TXT record %v.%v: %v\n", subDomain, domain, value)
	}
	return err
}

func deleteRecord(dnspodClient *dnspod.Client, domain string, recordId uint64) error {
	req := dnspod.NewDeleteRecordRequest()
	req.Domain = &domain
	req.RecordId = &recordId

	_, err := dnspodClient.DeleteRecord(req)
	if err == nil {
		fmt.Printf("deleted TXT record domain=%v recordId=%v\n", domain, recordId)
	}
	return err
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *customDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	dnspodClient, err := c.getDnspodClient(ch, ch.Config)
	if err != nil {
		return fmt.Errorf("get dnspod client fail: %w", err)
	}

	subDomain := extractSubDomain(ch.ResolvedFQDN, ch.ResolvedZone)

	record, err := findRecord(dnspodClient, ch.DNSName, subDomain, "TXT", ch.Key)
	if err != nil {
		return fmt.Errorf("find txt record fail domain=%s subDomain=%s: %w", ch.DNSName, subDomain, err)
	}

	if record != nil {
		return nil
	}

	err = createTXTRecord(dnspodClient, ch.DNSName, subDomain, ch.Key)
	if err != nil {
		return fmt.Errorf("create TXT record fail: %w", err)
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *customDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	dnspodClient, err := c.getDnspodClient(ch, ch.Config)
	if err != nil {
		return fmt.Errorf("get dnspod client fail: %w", err)
	}

	subDomain := extractSubDomain(ch.ResolvedFQDN, ch.ResolvedZone)
	record, err := findRecord(dnspodClient, ch.DNSName, subDomain, "TXT", ch.Key)
	if err != nil {
		return fmt.Errorf("find txt record fail domain=%s subDomain=%s: %w", ch.DNSName, subDomain, err)
	}

	if record != nil {
		err := deleteRecord(dnspodClient, ch.DNSName, *record.RecordId)
		if err != nil {
			return fmt.Errorf("delete record fail domain=%s subDomain=%d: %w", ch.DNSName, *record.RecordId, err)
		}
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	c.client = cl

	c.ctx = context.Background()
	c.dnspod = make(map[string]*dnspod.Client)

	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *apiextv1.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
