package daemon

import "github.com/ransoni/uchiwa/uchiwa/structs"

func (d *Daemon) buildDatacenter(name *string, info *structs.Info) *structs.Datacenter {
	datacenter := structs.Datacenter{
		Name:  *name,
		Info:  *info,
		Stats: make(map[string]int, 5),
	}

	return &datacenter
}
