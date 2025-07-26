package com.laroccasimone.ProgettoBD.Controller;

import kong.unirest.HttpResponse;
import kong.unirest.JsonNode;
import kong.unirest.Unirest;

import java.io.InputStream;
import java.security.MessageDigest;

public class VirusTotalAnalyzer {
    private static final String API_KEY = "f9e2631c66a8614498856992ea9e0be841fbc6acb7c7f822ba7e1ee09aeca8f6";
    // private static final String API_KEY = "77f78f3921d0b686a15499689d1b42e7072d7d40960a9c77fc067e443b883841";
    private static final String BASE_URL = "https://www.virustotal.com/api/v3/";

    // Analizza un indirizzo IP tramite l'API di VirusTotal
    public static String analyzeIp(String ip) {
        // Unirest.config().connectTimeout(20000); // Attendi 20 secondi

        // Invia una richiesta GET all'endpoint IP di VirusTotal, passando l’API key nell’header
        HttpResponse<JsonNode> response = Unirest.get(BASE_URL + "ip_addresses/" + ip)
                .header("x-apikey", API_KEY)
                .asJson();

        // Restituisce la risposta in formato JSON ben formattato (stringa)
        return response.getBody().toPrettyString();
    }

    // Analizza un file sospetto tramite l'API di VirusTotal
    public static String analyzeFile(InputStream fileStream) {
        // Unirest.config().connectTimeout(20000); // Attendi 20 secondi

        try {
            // Upload del file sul server di VirusTotal
            HttpResponse<JsonNode> uploadResponse = Unirest.post(BASE_URL + "files")
                    .header("x-apikey", API_KEY)
                    .field("file", fileStream, "sample.exe") // Nome fittizio
                    .asJson();

            // Se l’upload fallisce, restituisce errore
            if (uploadResponse.getStatus() != 200 && uploadResponse.getStatus() != 201) {
                return "Errore durante l'upload: " + uploadResponse.getStatusText();
            }

            // Ottiene l’ID dell’analisi dalla risposta
            String analysisId = uploadResponse.getBody()
                    .getObject()
                    .getJSONObject("data")
                    .getString("id");

            // Attende il completamento dell'analisi.
            // Massimo 10 tentativi.
            String status = "";
            JsonNode analysisResult = null;
            int attempts = 0;
            int maxAttempts = 10;

            while (attempts < maxAttempts) {
                // Invia richiesta GET per controllare lo stato dell’analisi
                HttpResponse<JsonNode> analysisResponse = Unirest.get(BASE_URL + "analyses/" + analysisId)
                        .header("x-apikey", API_KEY)
                        .asJson();

                // Estrae lo stato corrente (in-progress o completed)
                analysisResult = analysisResponse.getBody();
                status = analysisResult.getObject()
                        .getJSONObject("data")
                        .getJSONObject("attributes")
                        .getString("status");

                // Esce dal ciclo se lo stato è "completed"
                if ("completed".equalsIgnoreCase(status)) {
                    break;
                }

                // Attende 5 secondi prima del prossimo tentativo
                Thread.sleep(5000);
                attempts++;
            }

            // Se l’analisi non si è conclusa entro il numero massimo di tentativi,
            // restituisci un messaggio di errore
            if (!"completed".equalsIgnoreCase(status)) {
                return "Analisi non completata nei tempi previsti.";
            }

            // Restituisce il risultato finale in formato JSON leggibile
            return analysisResult.toPrettyString();

        } catch (Exception e) {
            e.printStackTrace();
            return "Errore durante l'analisi del file: " + e.getMessage();
        }
    }

    public static String computeSHA256(InputStream fileStream) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[8192];
        int read;
        while ((read = fileStream.read(buffer)) != -1) {
            digest.update(buffer, 0, read);
        }
        byte[] hash = digest.digest();
        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

}
