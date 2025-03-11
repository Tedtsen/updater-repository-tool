package cli

import (
	"fmt"
	"strings"
)

func AskConfirmation(retries int) bool {
	fmt.Println("Please type (y)es or (n)o and Enter to continue with the operation:")
	retryCount := 0
	return askConfirmation(retries, &retryCount)
}

func askConfirmation(retries int, retryCount *int) bool {
	var response string

	_, err := fmt.Scanln(&response)
	if err != nil {
		fmt.Printf("unrecognized confirmation input\n\terror: %v", err)
		return false
	}

	switch strings.ToLower(response) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		*retryCount++
		if *retryCount == retries {
			fmt.Printf("reached maximum retries: %d", retries)
			return false
		}
		fmt.Println("I'm sorry but I didn't get what you meant, please type (y)es or (n)o and then press enter:")
		return askConfirmation(retries, retryCount)
	}
}
