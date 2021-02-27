package cmd

import (
	"fmt"
	"os"
	"reflect"

	"strings"
	"text/template"

	cloudflare "github.com/cloudflare/cloudflare-go"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

type ParsedPolicyInclude struct {
	Items []string
	Id    string
}

const accessPolicyTemplate = `
resource "cloudflare_access_policy" "access_policy_{{.Policy.ID}}" {
    application_id = "{{.App.ID}}"
    zone_id = "{{.Zone.ID}}"
    name = "{{.Policy.Name}}"
    precedence = "{{.Policy.Precedence}}"
    decision = "{{.Policy.Decision}}"

{{- if .Policy.Include }}
    include {
  {{- if .ParsedPolicyInclude }}
    {{- range $k, $v := .ParsedPolicyInclude }}
	    {{- if eq $k "okta" }}
			okta {
				name = {{ $v.Items }}
				identity_provider_id = "{{ $v.Id }}"
			}
		{{- end }}
	    {{- if eq $k "email_domain" }}
	      email_domain = {{ $v.Items }}
		{{- end }}
	{{- end }}
  {{- else }}
  {{- range $k, $v := .Policy.Include }}
	{{- if isMap $v }}
		{{- range $k, $v := $v }}
			{{- if eq $k "everyone" }}
				{{ $k }} = "true"
			{{- else if eq $k "certificate" }}
				{{ $k }} = true
			{{- else }}
				{{ $k }} =  {{if isMap $v }} [ {{range $v}}"{{.}}",{{end}} ]  {{else}} "{{ $v }}" {{end}}
			{{- end }}
		{{- end }}
	{{- end }}
  {{- end}}
  {{- end}}
    }
{{- end }}

{{- if .Policy.Exclude }}
    exclude = {
{{- range $k, $v := .Policy.Exclude }}
    {{- if isMap $v }}
        {{- range $k, $v := $v }}
            {{ $k }} =  {{if isMap $v }} [{{range $v}}"{{.}}",{{end}}]  {{else}} "{{ $v }}" {{end}}
        {{- end}}
    {{- end }}
{{- end }}
    }
{{- end }}

{{- if .Policy.Require }}
    require = {
{{- range $k, $v := .Policy.Require }}
    {{- if isMap $v }}
        {{- range $k, $v := $v }}
            {{ $k }} =  {{if isMap $v }} [{{range $v}}"{{.}}",{{end}}]  {{else}} "{{ $v }}" {{end}}
        {{- end }}
    {{- end }}
{{- end }}
    }
{{- end }}
}
`

func init() {
	rootCmd.AddCommand(accessPolicyCmd)
}

var accessPolicyCmd = &cobra.Command{
	Use:   "access_policy",
	Short: "Import Access Policy data into Terraform",
	Run: func(cmd *cobra.Command, args []string) {
		log.Debug("Importing Access Policy data")

		for _, zone := range zones {
			log.WithFields(logrus.Fields{
				"ID":   zone.ID,
				"Name": zone.Name,
			}).Debug("Processing zone")

			accessApplications, _, appFetchErr := api.ZoneLevelAccessApplications(zone.ID, cloudflare.PaginationOptions{
				Page:    1,
				PerPage: 1000,
			})

			if appFetchErr != nil {
				log.Error(appFetchErr)
				return
			}

			for _, app := range accessApplications {

				accessPolicies, _, err := api.ZoneLevelAccessPolicies(zone.ID, app.ID, cloudflare.PaginationOptions{
					Page:    1,
					PerPage: 1000,
				})

				if err != nil {
					if strings.Contains(err.Error(), "HTTP status 403") {
						log.WithFields(logrus.Fields{
							"ID": zone.ID,
						}).Error("Insufficient permissions for accessing zone")
						continue
					}
					log.Error(err)
				}

				for _, policy := range accessPolicies {
					if tfstate {
						r := accessPolicyResourceStateBuild(app, policy, zone)
						resourcesMap["cloudflare_access_policy.access_policy_"+r.Primary.Id] = r
					} else {
						accessPolicyParse(app, policy, zone)
					}
				}
			}

		}
	},
}

func accessPolicyIncludeParse(policy cloudflare.AccessPolicy) map[string]ParsedPolicyInclude {
	m := make(map[string]ParsedPolicyInclude)
	if len(policy.Include) == 0 {
		return m
	}

	list := make([]string, 0, 5)
	var id string
	thisInclude := fmt.Sprintf("policy.Include %+v", policy.Include)
	log.Info(thisInclude)

	var includeKey string
	for _, include := range policy.Include {
		v := reflect.ValueOf(include)
		if v.Kind() == reflect.Map {
			for _, key := range v.MapKeys() {
				includeKey = key.String()
				if includeKey == "okta" {
					val := v.MapIndex(key)
					if val.Kind() == reflect.Interface {
						iface := val.Interface()
						myMap := iface.(map[string]interface{})
						for d, e := range myMap {

							if d == "identity_provider_id" {
								id = fmt.Sprintf("%v", e)
							}
							if d == "name" {
								list = append(list, fmt.Sprintf("\"%v\",", e))
							}
						}
					}
					pi := ParsedPolicyInclude{
						Items: list,
						Id:    id,
					}
					m["okta"] = pi
				}
				if includeKey == "email_domain" {
					val := v.MapIndex(key)
					if val.Kind() == reflect.Interface {
						iface := val.Interface()
						myMap := iface.(map[string]interface{})
						for d, e := range myMap {
							if d == "domain" {
								list = append(list, fmt.Sprintf("\"%v\",", e))
							}
						}
					}
					pi := ParsedPolicyInclude{
						Items: list,
						Id:    "",
					}
					m["email_domain"] = pi
				}
			}
		}
	}

	return m
}

func accessPolicyParse(app cloudflare.AccessApplication, policy cloudflare.AccessPolicy, zone cloudflare.Zone) {
	tmpl := template.Must(template.New("access_policy").Funcs(templateFuncMap).Parse(accessPolicyTemplate))
	formattedPolicyInclude := accessPolicyIncludeParse(policy)

	err := tmpl.Execute(os.Stdout,
		struct {
			App                 cloudflare.AccessApplication
			Policy              cloudflare.AccessPolicy
			ParsedPolicyInclude map[string]ParsedPolicyInclude
			Zone                cloudflare.Zone
		}{
			App:                 app,
			Policy:              policy,
			ParsedPolicyInclude: formattedPolicyInclude,
			Zone:                zone,
		})
	if err != nil {
		log.Error(err)
	}
}

func accessPolicyResourceStateBuild(app cloudflare.AccessApplication, policy cloudflare.AccessPolicy, zone cloudflare.Zone) Resource {
	r := Resource{
		Primary: Primary{
			Id: policy.ID,
			Attributes: map[string]string{
				"id":             policy.ID,
				"application_id": app.ID,
				"decision":       policy.Decision,
				"name":           policy.Name,
				"precedence":     fmt.Sprint(policy.Precedence),
				"zone_id":        zone.ID,
			},
			Meta:    make(map[string]string),
			Tainted: false,
		},
		DependsOn: []string{},
		Deposed:   []string{},
		Provider:  "provider.cloudflare",
		Type:      "cloudflare_access_policy",
	}

	attributes := r.Primary.Attributes.(map[string]string)

	flattenPolicy(attributes, "include", policy.Include)
	flattenPolicy(attributes, "exclude", policy.Exclude)
	flattenPolicy(attributes, "require", policy.Require)

	r.Primary.Attributes = attributes

	return r
}

func flattenPolicy(attributes map[string]string, name string, policy []interface{}) {
	if len(policy) > 0 {
		attributes[fmt.Sprintf("%s.#", name)] = "1"
	} else {
		attributes[fmt.Sprintf("%s.#", name)] = "0"
	}

	flattened := make(map[string][]string)
	for _, policyItem := range policy {
		policyItem = policyItem.(map[string]interface{})
		for k, v := range policyItem.(map[string]interface{}) {
			if _, ok := flattened[k]; !ok {
				flattened[k] = make([]string, 0)
			}
			for _, v1 := range v.(map[string]interface{}) {
				flattened[k] = append(flattened[k], v1.(string))
			}
		}
	}

	for k, v := range flattened {
		if k == "everyone" {
			attributes[fmt.Sprintf("%s.0.%s", name, k)] = "true"
			continue
		}
		attributes[fmt.Sprintf("%s.0.%s.#", name, k)] = fmt.Sprint(len(v))
		for k1, v1 := range v {
			attributes[fmt.Sprintf("%s.0.%s.%d", name, k, k1)] = v1
		}
	}
}
