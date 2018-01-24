package kerberos

import (
	"bytes"
	"fmt"
	"text/template"

	"github.com/go-ldap/ldap"
)

func EscapeLDAPValue(input string) string {
	// RFC4514 forbids un-escaped:
	// - leading space or hash
	// - trailing space
	// - special characters '"', '+', ',', ';', '<', '>', '\\'
	// - null
	for i := 0; i < len(input); i++ {
		escaped := false
		if input[i] == '\\' {
			i++
			escaped = true
		}
		switch input[i] {
		case '"', '+', ',', ';', '<', '>', '\\':
			if !escaped {
				input = input[0:i] + "\\" + input[i:]
				i++
			}
			continue
		}
		if escaped {
			input = input[0:i] + "\\" + input[i:]
			i++
		}
	}
	if input[0] == ' ' || input[0] == '#' {
		input = "\\" + input
	}
	if input[len(input)-1] == ' ' {
		input = input[0:len(input)-1] + "\\ "
	}
	return input
}

/*
 * Parses a distinguished name and returns the CN portion.
 * Given a non-conforming string (such as an already-extracted CN),
 * it will be returned as-is.
 */
func (b *backend) getCN(dn string) string {
	parsedDN, err := ldap.ParseDN(dn)
	if err != nil || len(parsedDN.RDNs) == 0 {
		// It was already a CN, return as-is
		return dn
	}

	for _, rdn := range parsedDN.RDNs {
		for _, rdnAttr := range rdn.Attributes {
			if rdnAttr.Type == "CN" {
				return rdnAttr.Value
			}
		}
	}

	// Default, return self
	return dn
}

/*
 * Returns the DN of the object representing the authenticated user.
 */
func (b *backend) getUserDN(cfg *ConfigEntry, c *ldap.Conn, bindDN string) (string, error) {
	userDN := ""
	if cfg.UPNDomain != "" {
		// Find the distinguished name for the user if userPrincipalName used for login
		filter := fmt.Sprintf("(userPrincipalName=%s)", ldap.EscapeFilter(bindDN))
		if b.Logger().IsDebug() {
			b.Logger().Debug("auth/ldap: Searching UPN", "userdn", cfg.UserDN, "filter", filter)
		}
		result, err := c.Search(&ldap.SearchRequest{
			BaseDN: cfg.UserDN,
			Scope:  2, // subtree
			Filter: filter,
		})
		if err != nil {
			return userDN, fmt.Errorf("LDAP search failed for detecting user: %v", err)
		}
		for _, e := range result.Entries {
			userDN = e.DN
		}
	} else {
		userDN = bindDN
	}

	return userDN, nil
}

/*
 * Discover and return the bind string for the user attempting to authenticate.
 * This is handled in one of several ways:
 *
 * 1. If DiscoverDN is set, the user object will be searched for using userdn (base search path)
 *    and userattr (the attribute that maps to the provided username).
 *    The bind will either be anonymous or use binddn and bindpassword if they were provided.
 * 2. If upndomain is set, the user dn is constructed as 'username@upndomain'. See https://msdn.microsoft.com/en-us/library/cc223499.aspx
 *
 */
func (b *backend) getUserBindDN(cfg *ConfigEntry, c *ldap.Conn, username string) (string, error) {
	bindDN := ""
	// TODO: fix this and remove && false. should probably work but some config is wrong
	if cfg.DiscoverDN || (cfg.BindDN != "" && cfg.BindPassword != "") && false {
		var err error
		if cfg.BindPassword != "" {
			err = c.Bind(cfg.BindDN, cfg.BindPassword)
		} else {
			err = c.UnauthenticatedBind(cfg.BindDN)
		}
		if err != nil {
			return bindDN, fmt.Errorf("LDAP bind (service) failed: %v", err)
		}

		filter := fmt.Sprintf("(%s=%s)", cfg.UserAttr, ldap.EscapeFilter(username))
		if b.Logger().IsDebug() {
			b.Logger().Debug("auth/ldap: Discovering user", "userdn", cfg.UserDN, "filter", filter)
		}
		result, err := c.Search(&ldap.SearchRequest{
			BaseDN: cfg.UserDN,
			Scope:  2, // subtree
			Filter: filter,
		})
		if err != nil {
			return bindDN, fmt.Errorf("LDAP search for binddn failed: %v", err)
		}
		if len(result.Entries) != 1 {
			return bindDN, fmt.Errorf("LDAP search for binddn 0 or not unique")
		}
		bindDN = result.Entries[0].DN
	} else {
		if cfg.UPNDomain != "" {
			bindDN = fmt.Sprintf("%s@%s", EscapeLDAPValue(username), cfg.UPNDomain)
		} else {
			bindDN = fmt.Sprintf("%s=%s,%s", cfg.UserAttr, EscapeLDAPValue(username), cfg.UserDN)
		}
	}

	return bindDN, nil
}

/*
 * getLdapGroups queries LDAP and returns a slice describing the set of groups the authenticated user is a member of.
 *
 * The search query is constructed according to cfg.GroupFilter, and run in context of cfg.GroupDN.
 * Groups will be resolved from the query results by following the attribute defined in cfg.GroupAttr.
 *
 * cfg.GroupFilter is a go template and is compiled with the following context: [UserDN, Username]
 *    UserDN - The DN of the authenticated user
 *    Username - The Username of the authenticated user
 *
 * Example:
 *   cfg.GroupFilter = "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))"
 *   cfg.GroupDN     = "OU=Groups,DC=myorg,DC=com"
 *   cfg.GroupAttr   = "cn"
 *
 * NOTE - If cfg.GroupFilter is empty, no query is performed and an empty result slice is returned.
 *
 */
func (b *backend) getLdapGroups(cfg *ConfigEntry, c *ldap.Conn, userDN string, username string) ([]string, error) {
	// retrieve the groups in a string/bool map as a structure to avoid duplicates inside
	ldapMap := make(map[string]bool)

	if cfg.GroupFilter == "" {
		b.Logger().Warn("auth/ldap: GroupFilter is empty, will not query server")
		return make([]string, 0), nil
	}

	if cfg.GroupDN == "" {
		b.Logger().Warn("auth/ldap: GroupDN is empty, will not query server")
		return make([]string, 0), nil
	}

	// If groupfilter was defined, resolve it as a Go template and use the query for
	// returning the user's groups
	if b.Logger().IsDebug() {
		b.Logger().Debug("auth/ldap: Compiling group filter", "group_filter", cfg.GroupFilter)
	}

	// Parse the configuration as a template.
	// Example template "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:={{.UserDN}}))"
	t, err := template.New("queryTemplate").Parse(cfg.GroupFilter)
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed due to template compilation error: %v", err)
	}

	// Build context to pass to template - we will be exposing UserDn and Username.
	context := struct {
		UserDN   string
		Username string
	}{
		ldap.EscapeFilter(userDN),
		ldap.EscapeFilter(username),
	}

	var renderedQuery bytes.Buffer
	t.Execute(&renderedQuery, context)

	if b.Logger().IsDebug() {
		b.Logger().Debug("auth/ldap: Searching", "groupdn", cfg.GroupDN, "rendered_query", renderedQuery.String())
	}

	result, err := c.Search(&ldap.SearchRequest{
		BaseDN: cfg.GroupDN,
		Scope:  2, // subtree
		Filter: renderedQuery.String(),
		Attributes: []string{
			cfg.GroupAttr,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("LDAP search failed: %v", err)
	}

	for _, e := range result.Entries {
		dn, err := ldap.ParseDN(e.DN)
		if err != nil || len(dn.RDNs) == 0 {
			continue
		}

		// Enumerate attributes of each result, parse out CN and add as group
		values := e.GetAttributeValues(cfg.GroupAttr)
		if len(values) > 0 {
			for _, val := range values {
				groupCN := b.getCN(val)
				ldapMap[groupCN] = true
			}
		} else {
			// If groupattr didn't resolve, use self (enumerating group objects)
			groupCN := b.getCN(e.DN)
			ldapMap[groupCN] = true
		}
	}

	ldapGroups := make([]string, 0, len(ldapMap))
	for key, _ := range ldapMap {
		ldapGroups = append(ldapGroups, key)
	}

	return ldapGroups, nil
}
