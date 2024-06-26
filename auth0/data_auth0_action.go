package auth0

import (
	"errors"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"gopkg.in/auth0.v5"
	"gopkg.in/auth0.v5/management"
)

func newDataAction() *schema.Resource {
	actionSchema := newComputedActionSchema()
	actionSchema["name"].Computed = false
	actionSchema["name"].Optional = false
	actionSchema["name"].Required = true
	return &schema.Resource{
		Read:   readDataAction,
		Schema: actionSchema,
	}
}

func newComputedActionSchema() map[string]*schema.Schema {
	actionSchema := newAction().Schema
	makeComputed(actionSchema)
	return actionSchema
}

func readDataAction(d *schema.ResourceData, m interface{}) error {
	name := auth0.StringValue(String(d, "name"))
	if name != "" {
		api := m.(*management.Management)
		actions, err := api.Action.List(management.Parameter("actionName", name))
		if err != nil {
			return err
		}
		for _, action := range actions.Actions {
			if auth0.StringValue(action.Name) == name {
				id := auth0.StringValue(action.ID)
				d.SetId(id)
				return readAction(d, m)
			}
		}
		return fmt.Errorf("no action found with 'name' = '%s'", name)
	} else {
		return errors.New("no 'name' was specified")
	}
}
