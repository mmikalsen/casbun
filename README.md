# CasBun
CasBun is a [Bun](https://bun.uptrace.dev/) ORM adapter for [Casbin](https://casbin.org/).
With this library, Casbin can load policy from bun supported database or save policy to it.


##  Installation 
```
go get github.com/mmikalsen/casbun
```

## Simple Example
```go
package main

import (
	"github.com/mmikalsen/casbun"
	"github.com/casbin/casbin/v2"
)

func main() {
	sqldb, _ := sql.Open(sqliteshim.ShimName, "file::memory:?cache=shared"")
	db := bun.NewDB(sqldb, sqlitedialect.New())

	a, _ := casbun.NewAdapter(ctx, db)
	e, _ := casbin.NewEnforcer("model.conf", a)

	// check the permission.
	_, _ = e.Enforce("alice", "data1", "read")

	// save the policy back to DB.
	_ = e.SavePolicy()
}
```

## Context Adapter 
`casbun` supports adapter with context, the following is a timeout control implemented using context

```go 
a, _ = casbun.NewAdapter(ctx, db)
// Limited time 300s
ctx, cancel := context.WithTimeout(context.Background(), 300*time.Microsecond)
defer cancel()
err := a.AddPolicyCtx(ctx, "p", "p", []string{"alice", "data1", "read"})
if err != nil {
    panic(err)
}
```

## Credits  
This adapter is a rewrite of the original
[junishimura/casbin-bun-adapter](https://github.com/JunNishimura/casbin-bun-adapter)
, with a focus on reducing unnecessary dependencies, preserving core
functionality, and improving the integration with Bun.


## License
casbin-bun-adapter is released under [MIT License](https://github.com/mmikalsen/casbun/blob/main/LICENSE).
