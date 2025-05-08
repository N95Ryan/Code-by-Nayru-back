package main

import (
	"encoding/json"
	"fmt"
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
		AllowedOrigins: []string{
			"https://codebynayru.com",
			"http://localhost:8080",
			"http://localhost:4321",
			"https://*.vercel.app",
		},
		AllowedMethods:   []string{"POST", "OPTIONS", "GET"},
		AllowedHeaders:   []string{"Content-Type", "Authorization"},
		AllowCredentials: true,
		Debug:            true,
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
	log.Printf("Nouvelle requête reçue - Méthode: %s, IP: %s", r.Method, r.RemoteAddr)

	if r.Method != http.MethodPost {
		log.Printf("Méthode non autorisée: %s", r.Method)
		http.Error(w, "Méthode non autorisée", http.StatusMethodNotAllowed)
		return
	}

	// Vérification du rate limiting
	ip := r.RemoteAddr
	if !limiter.isAllowed(ip) {
		log.Printf("Rate limit dépassé pour l'IP: %s", ip)
		sendResponse(w, false, "Veuillez attendre avant d'envoyer un nouveau message", http.StatusTooManyRequests)
		return
	}

	// Décodage du corps de la requête
	var form ContactForm
	if err := json.NewDecoder(r.Body).Decode(&form); err != nil {
		log.Printf("Erreur de décodage JSON: %v", err)
		sendResponse(w, false, "Erreur lors de la lecture des données", http.StatusBadRequest)
		return
	}

	log.Printf("Données reçues - Nom: %s, Email: %s, Message: %s", form.Name, form.Email, form.Message)

	// Validation des champs
	if form.Name == "" || form.Email == "" || form.Message == "" {
		log.Printf("Champs manquants dans la requête")
		sendResponse(w, false, "Tous les champs sont obligatoires", http.StatusBadRequest)
		return
	}

	// Envoi de l'email via Mailjet
	if err := SendMailJetEmail(form); err != nil {
		log.Printf("Erreur lors de l'envoi de l'email: %v", err)
		sendResponse(w, false, "Erreur lors de l'envoi du message", http.StatusInternalServerError)
		return
	}

	sendResponse(w, true, "Message envoyé avec succès", http.StatusOK)
}

func SendMailJetEmail(form ContactForm) error {
	// Configuration de Mailjet
	apiKeyPublic := os.Getenv("MJ_APIKEY_PUBLIC")
	apiKeyPrivate := os.Getenv("MJ_APIKEY_PRIVATE")

	if apiKeyPublic == "" || apiKeyPrivate == "" {
		log.Printf("ERREUR: Clés API Mailjet manquantes")
		return fmt.Errorf("configuration Mailjet incomplète")
	}

	mailjetClient := mailjet.NewMailjetClient(apiKeyPublic, apiKeyPrivate)

	log.Printf("Configuration Mailjet - Public Key: %s...", apiKeyPublic[:8])
	log.Printf("Configuration Mailjet - Private Key: %s...", apiKeyPrivate[:8])

	// Préparation de l'email
	messagesInfo := []mailjet.InfoMessagesV31{
		{
			From: &mailjet.RecipientV31{
				Email: "rpina.pro@gmail.com",
				Name:  "Code by Nayru",
			},
			To: &mailjet.RecipientsV31{
				mailjet.RecipientV31{
					Email: "rpina.pro@gmail.com",
					Name:  "Ryan PINA-SILASSE",
				},
			},
			Subject:  "Nouveau message de contact - Code by Nayru",
			TextPart: formatEmailText(form),
			HTMLPart: formatEmailHTML(form),
		},
	}

	log.Printf("Tentative d'envoi d'email à rpina.pro@gmail.com")

	// Envoi de l'email
	messages := mailjet.MessagesV31{Info: messagesInfo}
	response, err := mailjetClient.SendMailV31(&messages)

	if err != nil {
		log.Printf("ERREUR Mailjet détaillée: %+v", err)
		return fmt.Errorf("erreur lors de l'envoi de l'email: %v", err)
	}

	// Log détaillé de la réponse Mailjet
	log.Printf("Réponse Mailjet - Status: %d", response.ResultsV31[0].Status)
	log.Printf("Réponse Mailjet - To: %s", response.ResultsV31[0].To)
	log.Printf("Réponse Mailjet complète: %+v", response)

	return nil
}

func formatEmailText(form ContactForm) string {
	return `Nouveau message de contact

Nom: ` + form.Name + `
Email: ` + form.Email + `
Message: ` + form.Message
}

func formatEmailHTML(form ContactForm) string {
	return `
		<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
			<h2 style="color: #4a5568; margin-bottom: 20px;">Nouveau message de contact</h2>
			
			<div style="margin-bottom: 15px;">
				<strong style="color: #2d3748;">Nom:</strong>
				<p style="margin: 5px 0; color: #4a5568;">` + form.Name + `</p>
			</div>
			
			<div style="margin-bottom: 15px;">
				<strong style="color: #2d3748;">Email:</strong>
				<p style="margin: 5px 0; color: #4a5568;">` + form.Email + `</p>
			</div>
			
			<div style="margin-bottom: 15px;">
				<strong style="color: #2d3748;">Message:</strong>
				<p style="margin: 5px 0; color: #4a5568; white-space: pre-wrap;">` + form.Message + `</p>
			</div>
			
			<hr style="border: none; border-top: 1px solid #e0e0e0; margin: 20px 0;">
			
			<p style="color: #718096; font-size: 12px; margin: 0;">
				Ce message a été envoyé depuis le formulaire de contact de Code by Nayru.
			</p>
		</div>
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
