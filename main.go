package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/mailjet/mailjet-apiv3-go/v4"
	"github.com/rs/cors"
)

type ContactForm struct {
	Name    string `json:"name"`
	Email   string `json:"email"`
	Message string `json:"message"`
}

type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Structure pour la protection contre les spams
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string]time.Time
}

var limiter = RateLimiter{
	requests: make(map[string]time.Time),
}

func (rl *RateLimiter) isAllowed(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	lastRequest, exists := rl.requests[ip]
	if !exists {
		rl.requests[ip] = time.Now()
		return true
	}

	// Limite à une requête toutes les 30 secondes
	if time.Since(lastRequest) < 30*time.Second {
		return false
	}

	rl.requests[ip] = time.Now()
	return true
}

func main() {
	// Chargement des variables d'environnement
	if err := godotenv.Load(); err != nil {
		log.Println("Fichier .env non trouvé, utilisation des variables d'environnement système")
	}

	// Configuration CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"https://codebynayru.com", "http://localhost:3000"},
		AllowedMethods:   []string{"POST", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: true,
	})

	// Configuration des routes
	mux := http.NewServeMux()
	mux.HandleFunc("/api/contact", handleContact)

	// Démarrage du serveur
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	handler := c.Handler(mux)
	log.Printf("Serveur démarré sur le port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func handleContact(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Vérification du rate limiting
	ip := r.RemoteAddr
	if !limiter.isAllowed(ip) {
		sendResponse(w, false, "Veuillez attendre avant d'envoyer un nouveau message", http.StatusTooManyRequests)
		return
	}

	// Décodage du corps de la requête
	var form ContactForm
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		sendResponse(w, false, "Erreur lors de la lecture des données", http.StatusBadRequest)
		return
	}

	// Validation des champs
	if form.Name == "" || form.Email == "" || form.Message == "" {
		sendResponse(w, false, "Tous les champs sont obligatoires", http.StatusBadRequest)
		return
	}

	// Configuration de Mailjet
	mailjetClient := mailjet.NewMailjetClient(
		os.Getenv("MAILJET_API_KEY"),
		os.Getenv("MAILJET_API_SECRET"),
	)

	// Préparation de l'email
	messagesInfo := []mailjet.InfoMessagesV31{
		{
			From: &mailjet.RecipientV31{
				Email: "contact@codebynayru.com",
				Name:  "Code by Nayru",
			},
			To: &mailjet.RecipientsV31{
				mailjet.RecipientV31{
					Email: "rpina.pro@gmail.com",
					Name:  "Ryan Pina",
				},
			},
			Subject:  "Nouveau message de contact - Code by Nayru",
			TextPart: formatEmailText(form),
			HTMLPart: formatEmailHTML(form),
		},
	}

	// Envoi de l'email
	messages := mailjet.MessagesV31{Info: messagesInfo}
	_, err := mailjetClient.SendMailV31(&messages)
	if err != nil {
		log.Printf("Erreur lors de l'envoi de l'email: %v", err)
		sendResponse(w, false, "Erreur lors de l'envoi du message", http.StatusInternalServerError)
		return
	}

	sendResponse(w, true, "Message envoyé avec succès", http.StatusOK)
}

func formatEmailText(form ContactForm) string {
	return `Nouveau message de contact

Nom: ` + form.Name + `
Email: ` + form.Email + `
Message: ` + form.Message
}

func formatEmailHTML(form ContactForm) string {
	return `
		<h2>Nouveau message de contact</h2>
		<p><strong>Nom:</strong> ` + form.Name + `</p>
		<p><strong>Email:</strong> ` + form.Email + `</p>
		<p><strong>Message:</strong></p>
		<p>` + form.Message + `</p>
	`
}

func sendResponse(w http.ResponseWriter, success bool, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{
		Success: success,
		Message: message,
	})
}
