package com.laroccasimone.ProgettoBD.Model.CVE;

import com.mongodb.client.*;
import com.mongodb.client.model.Filters;
import com.mongodb.client.model.Updates;
import com.mongodb.client.result.InsertOneResult;
import org.bson.Document;
import org.bson.conversions.Bson;
import org.bson.types.ObjectId;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class CveDAO {
    private final MongoClient mongoClient;
    private final MongoDatabase database;
    private final MongoCollection<Document> malwareCollection;
    private final MongoCollection<Document> cveCollection;

    public CveDAO() {
        System.out.println("Inizio connessione ...");
        // Descrizione della connection string:
        //  localhost:27017,localhost:27018,localhost:27019: lista dei nodi del replica set,
        //  replicaSet=rs0: indica il nome del replica set,
        //  connectTimeoutMS=3000: massimo tempo (in ms) che il client attende per stabilire una connessione,
        //  serverSelectionTimeoutMS=3000: massimo tempo (in ms) per selezionare un nodo disponibile del replica set.
        mongoClient = MongoClients.create("mongodb://localhost:27017,localhost:27018,localhost:27019/?replicaSet=rs0&connectTimeoutMS=3000&serverSelectionTimeoutMS=3000");
        // Connection string alternative:
        // mongoClient = MongoClients.create("mongodb://localhost:27017");
        // mongoClient = MongoClients.create("mongodb://localhost:27017,localhost:27018,localhost:27019/?replicaSet=rs0");
        System.out.println("Connessione stabilita.");
        // Ottieni un riferimento al db cybersecurity
        database = mongoClient.getDatabase("cybersecurity");
        // Recupera le collection malware e cve
        malwareCollection = database.getCollection("malware");
        cveCollection = database.getCollection("cve");
    }

    // CREATE: Aggiungi una nuova CVE
    public void insertCve(Cve cve) {
        Document cveData = new Document()
                .append("id", cve.getCveId())
                .append("sourceIdentifier", cve.getSourceIdentifier())
                .append("published", cve.getPublished())
                .append("lastModified", cve.getLastModified())
                .append("vulnStatus", cve.getVulnStatus())
                .append("cveTags", cve.getCveTags())
                .append("descriptions", cve.getDescriptions())
                .append("metrics", cve.getMetrics())
                .append("weaknesses", cve.getWeaknesses())
                .append("configurations", cve.getConfigurations())
                .append("references", cve.getReferences());

        Document document = new Document("cve", cveData);

        InsertOneResult result = cveCollection.insertOne(document);
        System.out.println("Cve inserita con il seguente id: "
                + result.getInsertedId().asObjectId().getValue());
    }

    // READ: Trova tutte le CVE con gravità (baseScore) >= minScore
    public List<Document> findCveBySeverity(double minScore) {
        Bson filter = Filters.gte("cve.metrics.cvssMetricV2.0.cvssData.baseScore", minScore);
        return cveCollection.find(filter).into(new ArrayList<>());
    }

    // UPDATE: Aggiorna la baseScore di una CVE
    public void updateBaseScore(String cveId, double newScore) {
        Bson filter = Filters.eq("cve.id", cveId);
        Bson update = Updates.set("cve.metrics.cvssMetricV2.0.cvssData.baseScore", newScore);
        cveCollection.updateOne(filter, update);
        System.out.println("Gravità aggiornata per la CVE: " + cveId);
    }

    // DELETE: elimina una CVE con un dato ID
    public void deleteCve(String cveId) {
        cveCollection.deleteOne(Filters.eq("cve.id", cveId));
        System.out.println("CVE eliminata: " + cveId);
    }

    // JOIN: Trova tutte le CVE con severity >= 9.0 (baseScore) e associa, a ciascuna,
    // un array "malwareIds" contenente l'_id e l'Attack Name dei malware che la sfruttano.
    public List<Document> getHighSeverityCVEsWithMalware3(double minScore) {
        if (minScore == -1) {
            minScore = 9.0;
        }

        // Mappa una CVE ID a una lista di ID malware (String)
        Map<String, List<String>> cveToMalwareIds = new HashMap<>();
        // Pattern regex per trovare un riferimento a una CVE nel formato "CVE 2023-1234"
        Pattern cvePattern = Pattern.compile("CVE \\d{4}-\\d{4,7}", Pattern.CASE_INSENSITIVE);

        //Bson malwareFilter = Filters.exists("Attack Reference");

        // Itera su tutti i documenti nella collezione malware
        for (Document malware : malwareCollection.find()) {
            // Il campo "Attack Reference" contiene il riferimento alla CVE.
            // Nota: Ogni malware contiene al più un riferimento a CVE (Relazione del tipo (0, 1))
            String reference = malware.getString("Attack Reference");
            // Se il campo è nullo o vuoto, salta al prossimo documento
            if (reference == null || reference.isEmpty()) continue;

            // Ottieni un riferimento a un Matcher
            Matcher matcher = cvePattern.matcher(reference);
            // Usa la Regex per verificare la presenza di un riferimento CVE
            if (matcher.find()) {
                // Ottiene il riferimento alla CVE, e converte "CVE 2023-1234" in "CVE-2023-1234"
                String cveId = matcher.group().replace(" ", "-");
                // Ottiene l'ID del malware come stringa esadecimale
                String malwareId = malware.getObjectId("_id").toHexString();
                // Se la HashMap non contiene ancora questa CVE, crea una nuova lista vuota.
                // Poi aggiunge l'ID del malware alla lista dei malware associati a quella CVE.
                cveToMalwareIds.computeIfAbsent(cveId, k -> new ArrayList<>()).add(malwareId);
            }
        }

        // Filtro le CVE con baseScore >= minScore
        Bson scoreFilter = Filters.gte("cve.metrics.cvssMetricV2.0.cvssData.baseScore", minScore);
        List<Document> result = new ArrayList<>();

        // Itera sui documenti della collection cve che soddisfano il filtro
        for (Document cveDoc : cveCollection.find(scoreFilter)) {
            // Estrae l'ID della CVE dal documento (campo "cve.id")
            String cveId = ((Document) cveDoc.get("cve")).getString("id");
            // Recupera i malware associati a quella CVE (se presenti), altrimenti una lista vuota
            List<String> malwareIds = cveToMalwareIds.getOrDefault(cveId, Collections.emptyList());
            // Aggiunge al documento CVE un nuovo campo "malwareIds"
            cveDoc.append("malwareIds", malwareIds);
            // Aggiunge il documento CVE alla lista finale dei risultati
            result.add(cveDoc);
        }

        // Risultato JOIN: Lista di documenti cve della forma:
        // {
        //  "_id": ObjectId("68619acc730eaaf2eb6d1c27"),
        //  "cve": {
        //      "id": "CVE-2000-1234",
        //      ...
        //  }
        //  "malwareIds": [
        //    "66ae4c739c503c261566d55f",
        //    "66ae4c739c503c261566d560",
        //    "66ae4c739c503c261566d561"
        //  ]
        // }
        return result;
    }

    // Chiudi la connessione
    public void close() {
        mongoClient.close();
    }
}
