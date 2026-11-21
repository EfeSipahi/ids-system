package profile

// What a profile says of a request seen in traffic, for the dashboard's
// suggestions (W15 of docs/development-plan-dashboard-control.md).

// Fits returns the path of the endpoint that takes method and path, as the
// profile writes it, and whether one does.
func (p *Profile) Fits(method, path string) (string, bool) {
	if hasDotPart(path) {
		return "", false
	}
	ep, _, _ := p.find(method, path)
	if ep == nil {
		return "", false
	}
	return ep.pattern.text, true
}

// Knows reports whether the endpoint that takes method and path takes the
// parameter name from in (InQuery, InBody or InJSON): it names it there,
// or allows other parameters.
func (p *Profile) Knows(method, path, in, name string) bool {
	ep, _, _ := p.find(method, path)
	if ep == nil {
		return false
	}
	if ep.otherParams {
		return true
	}
	for _, prm := range ep.params {
		if prm.name == name && (prm.in == in || prm.in == InArgs && (in == InQuery || in == InBody)) {
			return true
		}
	}
	return false
}

// Endpoints returns how many endpoints the profile has.
func (p *Profile) Endpoints() int {
	return len(p.endpoints)
}
