package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
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
	Locale  string `json:"locale"`
}

type Response struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Structure pour la protection contre les spams
type RateLimiter struct {
	mu       sync.Mutex
	requests map[string]time.Time
	cleanup  *time.Ticker
}

func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string]time.Time),
		cleanup:  time.NewTicker(1 * time.Hour),
	}

	go rl.cleanupLoop()
	return rl
}

func (rl *RateLimiter) cleanupLoop() {
	for range rl.cleanup.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, lastRequest := range rl.requests {
			if now.Sub(lastRequest) > 24*time.Hour {
				delete(rl.requests, ip)
			}
		}
		rl.mu.Unlock()
	}
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

// Configuration CORS sécurisée
func setupCORS() *cors.Cors {
	return cors.New(cors.Options{
		AllowedOrigins: []string{
			"https://codebynayru.com",
			"https://www.codebynayru.com",
		},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Content-Type",
			"Origin",
			"Accept",
		},
		ExposedHeaders: []string{
			"Content-Length",
			"Content-Type",
		},
		AllowCredentials: true,
		MaxAge:           300,  // 5 minutes
		Debug:            true, // Activé pour le débogage
	})
}

// Middleware pour logger les requêtes CORS
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log des informations de la requête
		log.Printf("Requête reçue - Méthode: %s, Origine: %s, Chemin: %s, Headers: %v",
			r.Method,
			r.Header.Get("Origin"),
			r.URL.Path,
			r.Header,
		)

		// Vérification de l'origine
		origin := r.Header.Get("Origin")
		allowedOrigins := []string{"https://codebynayru.com", "https://www.codebynayru.com"}
		isAllowed := false
		for _, allowed := range allowedOrigins {
			if origin == allowed {
				isAllowed = true
				break
			}
		}

		if origin != "" && !isAllowed {
			log.Printf("Origine non autorisée: %s", origin)
			http.Error(w, "Origine non autorisée", http.StatusForbidden)
			return
		}

		// Gestion des requêtes OPTIONS
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Origin, Accept")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Max-Age", "300")
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type EmailTemplate struct {
	Name    string
	Email   string
	Message string
	Subject string
	Locale  string
}

func main() {
	// Chargement des variables d'environnement
	if err := godotenv.Load(); err != nil {
		log.Println("Fichier .env non trouvé, utilisation des variables d'environnement système")
	}

	// Définition de l'environnement
	if os.Getenv("ENV") == "" {
		os.Setenv("ENV", "development")
	}

	// Configuration CORS
	c := setupCORS()

	// Configuration des routes
	mux := http.NewServeMux()

	// Application du middleware CORS
	handler := corsMiddleware(c.Handler(mux))

	// Configuration des routes
	mux.HandleFunc("/api/contact", func(w http.ResponseWriter, r *http.Request) {
		handleContact(w, r, NewRateLimiter())
	})

	// Démarrage du serveur
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Serveur démarré sur le port %s en mode %s", port, os.Getenv("ENV"))
	log.Fatal(http.ListenAndServe(":"+port, handler))
}

func handleContact(w http.ResponseWriter, r *http.Request, limiter *RateLimiter) {
	log.Printf("Nouvelle requête reçue - Méthode: %s, IP: %s", r.Method, r.RemoteAddr)
	log.Printf("Headers reçus: %v", r.Header)

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

	// Lecture du corps de la requête
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Erreur de lecture du corps: %v", err)
		sendResponse(w, false, "Erreur lors de la lecture des données", http.StatusBadRequest)
		return
	}
	log.Printf("Corps de la requête reçu: %s", string(body))

	// Décodage du corps de la requête
	var form ContactForm
	if err := json.Unmarshal(body, &form); err != nil {
		log.Printf("Erreur de décodage JSON: %v", err)
		sendResponse(w, false, "Erreur lors de la lecture des données", http.StatusBadRequest)
		return
	}

	log.Printf("Données décodées: %+v", form)

	// Validation des champs
	if err := validateForm(form); err != nil {
		log.Printf("Erreur de validation: %v", err)
		sendResponse(w, false, err.Error(), http.StatusBadRequest)
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

// Nouvelle fonction de validation
func validateForm(form ContactForm) error {
	if form.Name == "" {
		return fmt.Errorf("le nom est obligatoire")
	}
	if len(form.Name) > 100 {
		return fmt.Errorf("le nom ne doit pas dépasser 100 caractères")
	}
	if form.Email == "" {
		return fmt.Errorf("l'email est obligatoire")
	}
	// Validation basique du format email
	if !strings.Contains(form.Email, "@") || !strings.Contains(form.Email, ".") {
		return fmt.Errorf("format d'email invalide")
	}
	if form.Message == "" {
		return fmt.Errorf("le message est obligatoire")
	}
	if len(form.Message) > 1000 {
		return fmt.Errorf("le message ne doit pas dépasser 1000 caractères")
	}
	return nil
}

func SendMailJetEmail(form ContactForm) error {
	// Configuration de Mailjet
	apiKeyPublic := os.Getenv("MJ_APIKEY_PUBLIC")
	apiKeyPrivate := os.Getenv("MJ_APIKEY_PRIVATE")

	log.Printf("Vérification des clés API Mailjet:")
	log.Printf("MJ_APIKEY_PUBLIC présent: %v", apiKeyPublic != "")
	log.Printf("MJ_APIKEY_PRIVATE présent: %v", apiKeyPrivate != "")

	if apiKeyPublic == "" || apiKeyPrivate == "" {
		log.Printf("ERREUR: Clés API Mailjet manquantes")
		return fmt.Errorf("configuration Mailjet incomplète")
	}

	// Validation du format des clés API
	if len(apiKeyPublic) != 32 || len(apiKeyPrivate) != 32 {
		log.Printf("ERREUR: Format des clés API Mailjet invalide")
		log.Printf("Longueur MJ_APIKEY_PUBLIC: %d", len(apiKeyPublic))
		log.Printf("Longueur MJ_APIKEY_PRIVATE: %d", len(apiKeyPrivate))
		return fmt.Errorf("format des clés API Mailjet invalide")
	}

	mailjetClient := mailjet.NewMailjetClient(apiKeyPublic, apiKeyPrivate)

	// Détermination du sujet en fonction de la locale
	subject := getEmailSubject(form.Locale)

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
					Name:  "Ryan PINA-SILASSE",
				},
			},
			Subject:  subject,
			TextPart: formatEmailText(form),
			HTMLPart: formatEmailHTML(form),
		},
	}

	log.Printf("Tentative d'envoi d'email à nouvelle-adresse-destinataire@votre-domaine.com (Locale: %s)", form.Locale)

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

func getEmailSubject(locale string) string {
	if locale == "en" {
		return "New contact message - Code by Nayru"
	}
	return "Nouveau message de contact - Code by Nayru"
}

func formatEmailText(form ContactForm) string {
	template := EmailTemplate{
		Name:    form.Name,
		Email:   form.Email,
		Message: form.Message,
		Subject: getEmailSubject(form.Locale),
		Locale:  form.Locale,
	}

	if form.Locale == "en" {
		return fmt.Sprintf("Name: %s\nEmail: %s\nMessage:\n%s", template.Name, template.Email, template.Message)
	}
	return fmt.Sprintf("Nom: %s\nEmail: %s\nMessage:\n%s", template.Name, template.Email, template.Message)
}

func formatEmailHTML(form ContactForm) string {
	// Remplacer les retours à la ligne par des <br>
	formattedMessage := strings.ReplaceAll(form.Message, "\n", "<br>")

	// Création du template avec les variables
	template := EmailTemplate{
		Name:    form.Name,
		Email:   form.Email,
		Message: formattedMessage,
		Subject: getEmailSubject(form.Locale),
		Locale:  form.Locale,
	}

	if form.Locale == "en" {
		return fmt.Sprintf(`
		<html>
			<head>
				<meta charset="utf-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>%s</title>
			</head>
			<body style="font-family: 'Google Sans', Roboto, Arial, sans-serif; color: #202124; font-size: 14px; line-height: 1.5; margin: 0; padding: 0; background-color: #f6f8fc;">
				<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
					<div style="background-color: white; border-radius: 8px; box-shadow: 0 1px 2px 0 rgba(60,64,67,0.3), 0 1px 3px 1px rgba(60,64,67,0.15); padding: 20px;">
						<div style="margin-bottom: 24px;">
							<div style="font-size: 16px; font-weight: 500; color: #202124; margin-bottom: 8px;">Subject: %s</div>
						</div>
						
						<div style="margin-bottom: 24px;">
							<div style="font-size: 14px; color: #5f6368; margin-bottom: 4px;">From:</div>
							<div style="font-size: 14px; color: #202124;">%s &lt;%s&gt;</div>
						</div>
						
						<div style="margin-bottom: 24px;">
							<div style="font-size: 14px; color: #5f6368; margin-bottom: 4px;">Message:</div>
							<div style="font-size: 14px; color: #202124; white-space: pre-wrap; background-color: #f8f9fa; padding: 12px; border-radius: 4px;">%s</div>
						</div>
						
						<div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #e0e0e0; color: #5f6368; font-size: 12px;">
							This message was sent from the Code by Nayru contact form.
						</div>
					</div>
				</div>
			</body>
		</html>
		`, template.Subject, template.Subject, template.Name, template.Email, template.Message)
	}
	return fmt.Sprintf(`
		<html>
			<head>
				<meta charset="utf-8">
				<meta name="viewport" content="width=device-width, initial-scale=1.0">
				<title>%s</title>
			</head>
			<body style="font-family: 'Google Sans', Roboto, Arial, sans-serif; color: #202124; font-size: 14px; line-height: 1.5; margin: 0; padding: 0; background-color: #f6f8fc;">
				<div style="max-width: 600px; margin: 0 auto; padding: 20px;">
					<div style="background-color: white; border-radius: 8px; box-shadow: 0 1px 2px 0 rgba(60,64,67,0.3), 0 1px 3px 1px rgba(60,64,67,0.15); padding: 20px;">
						<div style="margin-bottom: 24px;">
							<div style="font-size: 16px; font-weight: 500; color: #202124; margin-bottom: 8px;">Objet : %s</div>
						</div>
						
						<div style="margin-bottom: 24px;">
							<div style="font-size: 14px; color: #5f6368; margin-bottom: 4px;">De :</div>
							<div style="font-size: 14px; color: #202124;">%s &lt;%s&gt;</div>
						</div>
						
						<div style="margin-bottom: 24px;">
							<div style="font-size: 14px; color: #5f6368; margin-bottom: 4px;">Message :</div>
							<div style="font-size: 14px; color: #202124; white-space: pre-wrap; background-color: #f8f9fa; padding: 12px; border-radius: 4px;">%s</div>
						</div>
						
						<div style="margin-top: 24px; padding-top: 16px; border-top: 1px solid #e0e0e0; color: #5f6368; font-size: 12px;">
							Ce message a été envoyé depuis le formulaire de contact de Code by Nayru.
						</div>
					</div>
				</div>
			</body>
		</html>
	`, template.Subject, template.Subject, template.Name, template.Email, template.Message)
}

func sendResponse(w http.ResponseWriter, success bool, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(Response{
		Success: success,
		Message: message,
	})
}
