// Copyright Project Harbor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ldap

import (
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"
)

// FilterBuilder build filter for ldap search
type FilterBuilder struct {
	packet *ber.Packet
}

// Or ...
func (f *FilterBuilder) Or(filterB *FilterBuilder) *FilterBuilder {
	if f.packet == nil {
		return filterB
	}
	if filterB.packet == nil {
		return f
	}
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, goldap.FilterOr, nil, goldap.FilterMap[goldap.FilterOr])
	p.AppendChild(f.packet)
	p.AppendChild(filterB.packet)
	return &FilterBuilder{packet: p}
}

// And ...
func (f *FilterBuilder) And(filterB *FilterBuilder) *FilterBuilder {
	if f.packet == nil {
		return filterB
	}
	if filterB.packet == nil {
		return f
	}
	p := ber.Encode(ber.ClassContext, ber.TypeConstructed, goldap.FilterAnd, nil, goldap.FilterMap[goldap.FilterAnd])
	p.AppendChild(f.packet)
	p.AppendChild(filterB.packet)
	return &FilterBuilder{packet: p}
}

// String ...
func (f *FilterBuilder) String() (string, error) {
	if f.packet == nil {
		return "", nil
	}
	return goldap.DecompileFilter(f.packet)
}

// RemoveByPlaceholders removes all filter components that contain one of the given placeholders.
func (f *FilterBuilder) RemoveByPlaceholders(placeholders []string) {
	if f.packet == nil {
		return
	}
	f.packet = removeMatchingPacket(f.packet, placeholders)
}

// NewFilterBuilder parse FilterBuilder from string
func NewFilterBuilder(filter string) (*FilterBuilder, error) {
	f := normalizeFilter(filter)
	if len(strings.TrimSpace(f)) == 0 {
		return &FilterBuilder{}, nil
	}
	p, err := goldap.CompileFilter(f)
	if err != nil {
		return &FilterBuilder{}, ErrInvalidFilter
	}
	return &FilterBuilder{packet: p}, nil
}

// normalizeFilter - add '(' and ')' in ldap filter if it doesn't exist
func normalizeFilter(filter string) string {
	norFilter := strings.TrimSpace(filter)
	if len(norFilter) == 0 {
		return norFilter
	}
	if strings.HasPrefix(norFilter, "(") && strings.HasSuffix(norFilter, ")") {
		return norFilter
	}
	return "(" + norFilter + ")"
}

// removeMatchingPacket recursively traverses the filter packet tree
// and removes any packet (node) that contains one of the placeholders.
// Returns the cleaned packet or nil if the packet should be removed.
func removeMatchingPacket(p *ber.Packet, placeholders []string) *ber.Packet {
	if p == nil {
		return nil
	}
	// If this packet or its immediate children contain a placeholder, remove it entirely
	if packetOrImmediateChildContainsPlaceholder(p, placeholders) {
		return nil
	}
	// Otherwise, recursively process the children packets
	var newChildren []*ber.Packet
	for _, child := range p.Children {
		cleaned := removeMatchingPacket(child, placeholders)
		if cleaned != nil {
			newChildren = append(newChildren, cleaned)
		}
	}
	// If all children were removed but this node had children before, remove this node as well
	if len(newChildren) == 0 && len(p.Children) > 0 {
		return nil
	}
	// If this node is a logical AND or OR and has only one child left, flatten the node to simplify the filter
	if (p.Tag == goldap.FilterAnd || p.Tag == goldap.FilterOr) && len(newChildren) == 1 {
		return newChildren[0]
	}
	// Update the node's children to the filtered children and return it
	p.Children = newChildren
	return p
}

// packetOrImmediateChildContainsPlaceholder checks whether the given packet
// or any of its immediate children contain any of the specified placeholders in their string values.
func packetOrImmediateChildContainsPlaceholder(p *ber.Packet, placeholders []string) bool {
	if p == nil {
		return false
	}
	valsToCheck := []string{}
	// Check the value of this packet if it's a string
	if str, ok := p.Value.(string); ok {
		valsToCheck = append(valsToCheck, str)
	}
	// Also check the values of immediate child packets if they are strings
	for _, child := range p.Children {
		if child == nil {
			continue
		}
		if str, ok := child.Value.(string); ok {
			valsToCheck = append(valsToCheck, str)
		}
	}
	// Return true if any placeholder is found in any of the checked values
	for _, val := range valsToCheck {
		for _, ph := range placeholders {
			if strings.Contains(val, ph) {
				return true
			}
		}
	}
	return false
}