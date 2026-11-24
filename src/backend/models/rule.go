package models

import (
	"strings"
	"sync"

	"magitrickle/utils/intID"

	"github.com/dlclark/regexp2"
)

const (
	RuleTypeDomain    string = "domain"
	RuleTypeNamespace string = "namespace"
	RuleTypeWildcard  string = "wildcard"
	RuleTypeRegEx     string = "regex"
	RuleTypeSubnet    string = "subnet"
	RuleTypeSubnet6   string = "subnet6"
)

type Rule struct {
	ID     intID.ID
	Name   string
	Type   string
	Rule   string
	Enable bool

	compileOnce sync.Once
	compileWait sync.WaitGroup
	compileErr  error
	compiled    func(string) bool
}

func (d *Rule) IsEnabled() bool {
	return d.Enable
}

func (d *Rule) Compile() error {
	d.compileOnce.Do(func() {
		d.compileWait.Add(1)
		defer d.compileWait.Done()

		switch d.Type {
		case RuleTypeRegEx:
			re, err := regexp2.Compile(d.Rule, regexp2.IgnoreCase)
			if err != nil {
				d.compileErr = err
				d.compiled = func(string) bool { return false }
				return
			}
			d.compiled = func(s string) bool {
				ok, _ := re.MatchString(s)
				return ok
			}
		}
	})
	d.compileWait.Wait()
	return d.compileErr
}

func (d *Rule) IsMatch(domainName string) bool {
	switch d.Type {
	case RuleTypeDomain:
		return domainName == d.Rule

	case RuleTypeNamespace:
		return matchNamespace(d.Rule, domainName)

	case RuleTypeWildcard:
		if !WildcardHasGlob(d.Rule) {
			return matchNamespace(d.Rule, domainName)
		}
		return MatchWildcardGlob(d.Rule, domainName)

	case RuleTypeRegEx:
		err := d.Compile()
		if err != nil {
			return false
		}
		return d.compiled(domainName)

	case RuleTypeSubnet, RuleTypeSubnet6:
		return false
	}
	return false
}

func matchNamespace(pattern, name string) bool {
	if name == pattern {
		return true
	}
	boundary := len(name) - len(pattern) - 1
	return boundary >= 0 && name[boundary] == '.' && name[boundary+1:] == pattern
}

// WildcardHasGlob distinguishes glob patterns from legacy namespace rules.
func WildcardHasGlob(pattern string) bool {
	return strings.ContainsAny(pattern, "*?")
}

// MatchWildcardGlob matches '*' against zero or more bytes and '?' against
// exactly one byte. Other bytes, including dots, are literal.
func MatchWildcardGlob(pattern, name string) bool {
	patternIndex, nameIndex := 0, 0
	lastStar, retry := -1, 0
	for nameIndex < len(name) {
		switch {
		case patternIndex < len(pattern) && pattern[patternIndex] == '*':
			lastStar, retry = patternIndex, nameIndex
			patternIndex++
		case patternIndex < len(pattern) && (pattern[patternIndex] == '?' || pattern[patternIndex] == name[nameIndex]):
			patternIndex++
			nameIndex++
		case lastStar >= 0:
			retry++
			patternIndex, nameIndex = lastStar+1, retry
		default:
			return false
		}
	}
	for patternIndex < len(pattern) && pattern[patternIndex] == '*' {
		patternIndex++
	}
	return patternIndex == len(pattern)
}
