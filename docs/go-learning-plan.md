# Go Learning Plan for the IDS Project

Created: 5 October 2026
Reader: a developer who knows Python and is new to Go
Goal: be able to read and review the Go code in this repository, starting with `internal/seclang`.

**Note:** The course section list below is written from memory and was not checked against the course page on the date above. If the section names differ, match them by topic.

## 1. The plan

One course, minus its last project, plus about one hour of extra material.

| Step | What | Time |
| --- | --- | --- |
| 1 | Udemy course "Go - The Complete Guide" (Maximilian Schwarzmüller), selected sections | About 10 hours |
| 2 | Article on strings, bytes and runes | 30 minutes |
| 3 | Official testing tutorial | 20 minutes |
| 4 | Read our parser code and do the final check | 1 to 2 hours |

Course link: <https://www.udemy.com/course/go-the-complete-guide/>

## 2. Step 1 — The course

| Sections | Watch? | Why |
| --- | --- | --- |
| Basics, packages, modules | Yes | The layout of this repository: `go.mod`, packages, `internal/` |
| Functions, control structures | Yes, at 1.5x speed | Familiar from Python; only the syntax is new |
| Pointers | Yes, carefully | Decides whether a function gets a copy or the original. Needed for M21: shared rules versus per-request state |
| Structs and custom types | Yes, carefully | `Directive`, `Variable`, `Operator`, `Action` are all structs |
| Interfaces and generics | Interfaces carefully, generics once | Operators and transformations will each be one small interface |
| Arrays, slices, maps | Yes, carefully | Lists of rules; the per-request `TX` variables will be a map |
| Error handling, working with files | Yes | Every parser function returns `(value, error)` |
| Concurrency: goroutines and channels | Yes | Needed when the engine handles many requests at once |
| REST API project (Gin framework, SQL database, authentication) | **Skip** | This project uses none of it |

Type the examples yourself while watching. Do not copy and paste.

## 3. Step 2 — Strings, bytes and runes

Read: [Strings, bytes, runes and characters in Go](https://go.dev/blog/strings)

Why: attack payloads contain invalid UTF-8, null bytes and unusual encodings, and every transformation in the engine works on them. This matters more here than in a typical Go project, and the course does not go deep on it.

You have understood it when you can answer:

1. Why is `len("ş")` equal to 2?
2. What does `for i, r := range s` give you in `i` and in `r`?
3. What is the difference between `s[0]` and the first rune of `s`?

## 4. Step 3 — Testing

Do: [Tutorial: Add a test](https://go.dev/doc/tutorial/add-a-test)

Why: every step of this project is written with tests, and the course covers testing lightly or not at all.

Then open `internal/seclang/syntax_test.go` and read `TestParseOperator`. It is a table-driven test, the standard Go style: a list of inputs with expected outputs, and one loop that checks each.

## 5. Step 4 — Read our code

Read the files in `internal/seclang/` in this order:

| File | What to look for |
| --- | --- |
| `directive.go` | Structs, methods, constants with `iota`, a custom error type |
| `operator.go` | A small function that returns `(value, error)` |
| `actions.go` | Walking through a string by index, slices, `strings.Builder` |
| `variables.go` | The same ideas with one more level of detail |
| `reader.go` | Reading a file line by line |
| `parser.go` | How the pieces are combined; chain tracking |

Run the tests while you read:

```
cd /home/esip/Documents/ids-system
go test -v ./internal/seclang/
```

## 6. Final check

You are done when you can do all three:

1. Explain what every line of `operator.go` and `actions.go` does.
2. Add a new case to `TestParseOperator` in `syntax_test.go`, for example `"@ge 5"`, and see it pass.
3. Change the expected value of that case to something wrong, run the tests, and read the failure message.

After that, review of step 2 of the engine (`internal/httpmodel`) can begin.

## 7. Later, when the project needs it

Not part of this plan. Listed so they are not a surprise.

| When the project reaches | Topic to learn then |
| --- | --- |
| JSON and multipart bodies | `encoding/json` in depth, `mime/multipart` |
| Live traffic from the proxy | `context`, worker pools, `net/http` server |
| The ML model | cgo and ONNX Runtime |
| Performance targets | Benchmarks and `pprof` |
