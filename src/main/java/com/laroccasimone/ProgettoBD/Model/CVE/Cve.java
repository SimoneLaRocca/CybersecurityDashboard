package com.laroccasimone.ProgettoBD.Model.CVE;

import java.util.List;

// CVE (Common Vulnerabilities and Exposures)
public class Cve {

    // Identificatore univoco generato da MongoDB
    private String id;
    // Codice identificativo della vulnerabilità secondo lo standard CVE
    private String cveId;
    // Fonte che ha riportato la vulnerabilità (es. cve@mitre.org)
    private String sourceIdentifier;
    // Data di pubblicazione della vulnerabilità
    private String published;
    // Data dell'ultima modifica registrata sulla vulnerabilità
    private String lastModified;
    // Stato attuale della vulnerabilità (es. Published, Deferred, Rejected)
    private String vulnStatus;
    // Elenco di tag associati alla vulnerabilità (se presenti)
    private List<String> cveTags;
    // Elenco di descrizioni in diverse lingue
    private List<String> descriptions;
    // Descrizione semplificata delle metriche CVSS
    // (Common Vulnerability Scoring System)
    // (esempio: punteggio base, severità, ecc...)
    private String metrics;
    // Elenco dei codici CWE (Common Weakness Enumeration) associati alla vulnerabilità
    private List<String> weaknesses;
    // Elenco dei criteri di configurazione dei prodotti affetti
    private List<String> configurations;
    // Elenco dei riferimenti esterni
    private List<String> references;

    public Cve() {
    }

    public Cve(String id, String cveId, String sourceIdentifier, String published,
               String lastModified, String vulnStatus, List<String> cveTags,
               List<String> descriptions, String metrics, List<String> weaknesses,
               List<String> configurations, List<String> references) {
        this.id = id;
        this.cveId = cveId;
        this.sourceIdentifier = sourceIdentifier;
        this.published = published;
        this.lastModified = lastModified;
        this.vulnStatus = vulnStatus;
        this.cveTags = cveTags;
        this.descriptions = descriptions;
        this.metrics = metrics;
        this.weaknesses = weaknesses;
        this.configurations = configurations;
        this.references = references;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getCveId() {
        return cveId;
    }

    public void setCveId(String cveId) {
        this.cveId = cveId;
    }

    public String getSourceIdentifier() {
        return sourceIdentifier;
    }

    public void setSourceIdentifier(String sourceIdentifier) {
        this.sourceIdentifier = sourceIdentifier;
    }

    public String getPublished() {
        return published;
    }

    public void setPublished(String published) {
        this.published = published;
    }

    public String getLastModified() {
        return lastModified;
    }

    public void setLastModified(String lastModified) {
        this.lastModified = lastModified;
    }

    public String getVulnStatus() {
        return vulnStatus;
    }

    public void setVulnStatus(String vulnStatus) {
        this.vulnStatus = vulnStatus;
    }

    public List<String> getCveTags() {
        return cveTags;
    }

    public void setCveTags(List<String> cveTags) {
        this.cveTags = cveTags;
    }

    public List<String> getDescriptions() {
        return descriptions;
    }

    public void setDescriptions(List<String> descriptions) {
        this.descriptions = descriptions;
    }

    public String getMetrics() {
        return metrics;
    }

    public void setMetrics(String metrics) {
        this.metrics = metrics;
    }

    public List<String> getWeaknesses() {
        return weaknesses;
    }

    public void setWeaknesses(List<String> weaknesses) {
        this.weaknesses = weaknesses;
    }

    public List<String> getConfigurations() {
        return configurations;
    }

    public void setConfigurations(List<String> configurations) {
        this.configurations = configurations;
    }

    public List<String> getReferences() {
        return references;
    }

    public void setReferences(List<String> references) {
        this.references = references;
    }
}

