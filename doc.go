// Package auth provides authentication primitives (JWT issuance, stateful
// repositories, HTTP helpers) plus lifecycle extension points for downstream
// admin workflows.
//
// User lifecycle:
//   - Users carry a UserStatus field that is persisted via Bun. Statuses cover
//     pending, active, suspended, disabled, and archived flows so every product
//     can opt into the same invariants.
//   - UserStateMachine centralizes the transition graph, timestamp handling,
//     hooks, and persistence. Embed the shared Users repository and invoke
//     Transition with ActorRef metadata whenever an admin moves an account.
//
// Activity sinks:
//   - ActivitySink is a light-weight audit emitter used by Auther and the state
//     machine to describe lifecycle, login, impersonation, and password reset
//     events. Sinks run best-effort (errors are logged) so you can forward to a
//     database or queue without blocking authentication.
//
// Claims decoration:
//   - ClaimsDecorator is invoked before JWTs are signed. Decorators may enrich
//     extension fields such as resource roles or metadata while protected claims
//     (sub, iss, aud, exp, etc.) remain immutable. Combine WithClaimsDecorator
//     with ActivitySink to keep lifecycle state and issued tokens consistent.
package auth
