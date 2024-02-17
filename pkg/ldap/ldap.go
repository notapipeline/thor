// This file is part of thor (https://github.com/notapipeline/thor).
//
// Copyright (c) 2024 Martin Proffitt <mproffitt@choclab.net>.
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
// PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

package ldap

/// Perform LDAP connection and search for employee

import (
	"fmt"
	"strings"

	"gopkg.in/ldap.v2"
)

const (
	ldapServer   = "ad.example.com:389"
	ldapBind     = "search@example.com"
	ldapPassword = "Password123!"

	filterDN = "(&(objectClass=person)(memberOf:1.2.840.113556.1.4.1941:=CN=Chat,CN=Users,DC=example,DC=com)(|(sAMAccountName={username})(mail={username})))"
	baseDN   = "CN=Users,DC=example,DC=com"

	loginUsername = "tboerger"
	loginPassword = "password"
)

/*
	func main() {
		conn, err := connect()

		if err != nil {
			fmt.Printf("Failed to connect. %s", err)
			return
		}

		defer conn.Close()

		if err := list(conn); err != nil {
			fmt.Printf("%v", err)
			return
		}

		if err := auth(conn); err != nil {
			fmt.Printf("%v", err)
			return
		}
	}
*/
func connect() (*ldap.Conn, error) {
	conn, err := ldap.Dial("tcp", ldapServer)

	if err != nil {
		return nil, fmt.Errorf("Failed to connect. %s", err)
	}

	if err := conn.Bind(ldapBind, ldapPassword); err != nil {
		return nil, fmt.Errorf("Failed to bind. %s", err)
	}

	return conn, nil
}

func list(conn *ldap.Conn) error {
	result, err := conn.Search(ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter("*"),
		[]string{"dn", "sAMAccountName", "mail", "sn", "givenName"},
		nil,
	))

	if err != nil {
		return fmt.Errorf("Failed to search users. %s", err)
	}

	for _, entry := range result.Entries {
		fmt.Printf(
			"%s: %s %s -- %v -- %v\n",
			entry.DN,
			entry.GetAttributeValue("givenName"),
			entry.GetAttributeValue("sn"),
			entry.GetAttributeValue("sAMAccountName"),
			entry.GetAttributeValue("mail"),
		)
	}

	return nil
}

func auth(conn *ldap.Conn) error {
	result, err := conn.Search(ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter(loginUsername),
		[]string{"dn"},
		nil,
	))

	if err != nil {
		return fmt.Errorf("Failed to find user. %s", err)
	}

	if len(result.Entries) < 1 {
		return fmt.Errorf("User does not exist")
	}

	if len(result.Entries) > 1 {
		return fmt.Errorf("Too many entries returned")
	}

	if err := conn.Bind(result.Entries[0].DN, loginPassword); err != nil {
		fmt.Printf("Failed to auth. %s", err)
	} else {
		fmt.Printf("Authenticated successfuly!")
	}

	return nil
}

func filter(needle string) string {
	res := strings.Replace(
		filterDN,
		"{username}",
		needle,
		-1,
	)

	return res
}
