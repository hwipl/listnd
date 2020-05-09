package cmd

// vnetMap stores mappings from vnet IDs to vnet information
type vnetMap struct {
	m map[uint32]*vnetInfo
}

// Add adds a vnet with id to the mapping and returns the vnet info
func (v *vnetMap) Add(id uint32) *vnetInfo {
	if v.m[id] == nil {
		debug("Adding new vnet entry")
		vnet := vnetInfo{
			ID: id,
		}
		v.m[id] = &vnet
	}
	return v.m[id]
}

// Get returns the vnet info with id
func (v *vnetMap) Get(id uint32) *vnetInfo {
	if v.m == nil {
		return nil
	}
	return v.m[id]
}
