package audit

import "github.com/ransoni/uchiwa/uchiwa/structs"

// Log writes to audit log (Sensu Enterprise only)
var Log func(structs.AuditLog) error

func LogMock(log structs.AuditLog) error {
	return nil
}
