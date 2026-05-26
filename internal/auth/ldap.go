package auth

import (
    "fmt"
    "strings"

    "github.com/go-ldap/ldap/v3"
)

type ADUser struct {
	GUID       string
	Username   string
	FullName   string
	Department string
	Position   string
}

type LDAPConfig struct {
    Server        string
    BindDN        string
    BindPassword  string
    BaseDN        string
    RequiredGroup string
}

type AuthService struct {
    cfg LDAPConfig
}

func NewAuthService(cfg LDAPConfig) *AuthService {
    return &AuthService{cfg: cfg}
}

func (a *AuthService) LdapAuthenticate(username, password string) (*ADUser, error) {
    l, err := ldap.Dial("tcp", a.cfg.Server)
    if err != nil {
        return nil, fmt.Errorf("ldap connect error: %v", err)
    }
    defer l.Close()

    if err = l.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
        return nil, fmt.Errorf("ldap admin bind error: %v", err)
    }

    searchRequest := ldap.NewSearchRequest(
        a.cfg.BaseDN,
        ldap.ScopeWholeSubtree,
        ldap.NeverDerefAliases,
        0, 0, false,
        fmt.Sprintf("(&(objectClass=user)(sAMAccountName=%s))", ldap.EscapeFilter(username)),
        []string{
            "displayName",
            "userAccountControl",
            "memberOf",
            "distinguishedName",
            "physicalDeliveryOfficeName",
            "description",
        },
        nil,
    )

    sr, err := l.Search(searchRequest)
    if err != nil {
        return nil, err
    }

    if len(sr.Entries) != 1 {
        return nil, fmt.Errorf("user not found")
    }

    entry := sr.Entries[0]

    // Проверка группы
    isAllowed := false
    for _, group := range entry.GetAttributeValues("memberOf") {
        if strings.EqualFold(group, a.cfg.RequiredGroup) {
            isAllowed = true
            break
        }
    }

    if !isAllowed {
        return nil, fmt.Errorf("no access group")
    }

    // bind user
    if err = l.Bind(entry.DN, password); err != nil {
        return nil, fmt.Errorf("invalid credentials")
    }

    return &ADUser{
        Username:   username,
        FullName:   entry.GetAttributeValue("displayName"),
        Department: entry.GetAttributeValue("physicalDeliveryOfficeName"),
        Position:   entry.GetAttributeValue("description"),
    }, nil
}