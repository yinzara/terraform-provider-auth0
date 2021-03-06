package auth0

import (
	"net/http"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"

	"gopkg.in/auth0.v4"
	"gopkg.in/auth0.v4/management"
)

func newCustomDomain() *schema.Resource {
	return &schema.Resource{

		Create: createCustomDomain,
		Read:   readCustomDomain,
		Update: autoVerifyCustomDomain,
		Delete: deleteCustomDomain,
		Importer: &schema.ResourceImporter{
			State: schema.ImportStatePassthrough,
		},

		Schema: map[string]*schema.Schema{
			"domain": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"type": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: validation.StringInSlice([]string{
					"auth0_managed_certs",
					"self_managed_certs",
				}, true),
			},
			"primary": {
				Type:     schema.TypeBool,
				Computed: true,
			},
			"status": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"auto_verify": {
				Type:     schema.TypeBool,
				Optional: true,
			},
			"verification_method": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice([]string{"txt"}, true),
			},
			"verification": {
				Type:     schema.TypeList,
				Computed: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"methods": {
							Type:     schema.TypeList,
							Elem:     schema.TypeMap,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func createCustomDomain(d *schema.ResourceData, m interface{}) error {
	c := buildCustomDomain(d)
	api := m.(*management.Management)
	if err := api.CustomDomain.Create(c); err != nil {
		return err
	}
	d.SetId(auth0.StringValue(c.ID))

	_ = autoVerifyCustomDomain(d, m) // attempt but don't error if it fails on create
	return readCustomDomain(d, m)
}

func readCustomDomain(d *schema.ResourceData, m interface{}) error {
	api := m.(*management.Management)
	c, err := api.CustomDomain.Read(d.Id())
	if err != nil {
		if mErr, ok := err.(management.Error); ok {
			if mErr.Status() == http.StatusNotFound {
				d.SetId("")
				return nil
			}
		}
		return err
	}

	d.SetId(auth0.StringValue(c.ID))
	d.Set("domain", c.Domain)
	d.Set("type", c.Type)
	d.Set("primary", c.Primary)
	d.Set("status", c.Status)

	if auth0.BoolValue(Bool(d, "auto_verify")) && auth0.StringValue(String(d, "status")) == "pending_verification" {
		d.Set("auto_verify", false) // this ensures the record keeps needing to be updated until it is verified
	}

	if c.Verification != nil {
		d.Set("verification", []map[string]interface{}{
			{"methods": c.Verification.Methods},
		})
	}

	return nil
}

func deleteCustomDomain(d *schema.ResourceData, m interface{}) error {
	api := m.(*management.Management)
	err := api.CustomDomain.Delete(d.Id())
	if err != nil {
		if mErr, ok := err.(management.Error); ok {
			if mErr.Status() == http.StatusNotFound {
				d.SetId("")
				return nil
			}
		}
	}
	return err
}

func buildCustomDomain(d *schema.ResourceData) *management.CustomDomain {
	return &management.CustomDomain{
		Domain:             String(d, "domain"),
		Type:               String(d, "type"),
		VerificationMethod: String(d, "verification_method"),
	}
}

func autoVerifyCustomDomain(d *schema.ResourceData, m interface{}) error {
	if auth0.BoolValue(Bool(d, "auto_verify")) && auth0.StringValue(String(d, "status")) == "pending_verification" {
		api := m.(*management.Management)
		if _, err := api.CustomDomain.Verify(d.Id()); err != nil {
			return err
		}
	}
	return nil
}
