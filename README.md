# Go Auth


```go
dispatcher.SubscribeCommand(&RegisterUserHandler{
	repo: app.RepositoryManager(),
})

// Dispatch a command.
createMsg := RegisterUserMessage{Email: "Bob"}
if err := dispatcher.Dispatch(context.Background(), createMsg); err != nil {
	fmt.Println("Dispatch error:", err)
}
```


