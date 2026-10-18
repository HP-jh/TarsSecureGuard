package main

import "fmt"

func printBanner() {
	fmt.Println("╔══════════════════════════════════════╗")
	fmt.Println("║     TarsSecureGuard Gateway          ║")
	fmt.Printf("║     Version %-26s ║\n", version)
	fmt.Println("╚══════════════════════════════════════╝")
}
