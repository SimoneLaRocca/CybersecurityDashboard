package com.laroccasimone.ProgettoBD.Controller;

import com.laroccasimone.ProgettoBD.Model.CVE.Cve;
import com.laroccasimone.ProgettoBD.Model.CVE.CveDAO;
import com.laroccasimone.ProgettoBD.Model.Malware.Malware;
import com.laroccasimone.ProgettoBD.Model.Malware.MalwareDAO;

import javax.servlet.*;
import javax.servlet.http.*;
import javax.servlet.annotation.*;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

import org.bson.Document;

@WebServlet(name = "UserInterfaceDBServlet", urlPatterns = "/UserInterfaceDBServlet/*")
@MultipartConfig
public class UserInterfaceDBServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String pattern = (request.getPathInfo() == null ? "/" : request.getPathInfo());
        String path = null;
        MalwareDAO malwareDAO = new MalwareDAO();
        CveDAO cveDAO = new CveDAO();

        switch (pattern){
            case "/findMalwareByCve":
                // Ricerca malware che sfruttano una certa CVE
                String cveId = request.getParameter("cveId");
                List<Document> malwareList = malwareDAO.findMalwareByCVE(cveId);
                request.setAttribute("malwareList", malwareList);
                break;

            case "/findMalwareByCategory":
                // Ricerca malware per categoria
                String category = request.getParameter("category");
                List<Document> malwareByCategory = malwareDAO.findMalwareByAttackCategory(category);
                request.setAttribute("malwareList", malwareByCategory);
                break;

            case "/findCveBySeverity":
                // Ricerca CVE con gravità maggiore o uguale a un certo valore
                double minScore = Double.parseDouble(request.getParameter("minSeverity"));
                List<Document> cveList = cveDAO.findCveBySeverity(minScore);
                request.setAttribute("cveList", cveList);
                break;

            case "/getHighSeverityCVEsWithMalware":
                // JOIN: CVE con gravità maggiore uguale a un valore dato,
                // più una lista di malware che le sfruttano
                double threshold = Double.parseDouble(request.getParameter("threshold"));
                List<Document> joined = cveDAO.getHighSeverityCVEsWithMalware3(threshold);
                request.setAttribute("joinedResults", joined);
                break;

            default:
                break;
        }

        malwareDAO.close();
        cveDAO.close();

        path = "/index.jsp";
        RequestDispatcher rd = request.getRequestDispatcher(path);
        rd.forward(request,response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String pattern = (request.getPathInfo() == null ? "/" : request.getPathInfo());
        String path = null;
        MalwareDAO malwareDAO = new MalwareDAO();
        CveDAO cveDAO = new CveDAO();

        switch (pattern){
            case "/createMalware":
                // Inserisci una malware nella collection
                Malware malware = new Malware();
                malware.setStartTime(Long.parseLong(request.getParameter("startTime")));
                malware.setLastTime(Long.parseLong(request.getParameter("lastTime")));
                malware.setAttackCategory(request.getParameter("attackCategory"));
                malware.setAttackSubcategory(request.getParameter("attackSubcategory"));
                malware.setProtocol(request.getParameter("protocol"));
                malware.setSourceIP(request.getParameter("sourceIP"));
                malware.setSourcePort(Integer.parseInt(request.getParameter("sourcePort")));
                malware.setDestinationIP(request.getParameter("destinationIP"));
                malware.setDestinationPort(Integer.parseInt(request.getParameter("destinationPort")));
                malware.setAttackName(request.getParameter("attackName"));
                malware.setAttackReference(request.getParameter("attackReference"));
                malwareDAO.insertMalware(malware);
                break;

            case "/createCve":
                // Inserisci una cve nella collection
                Cve cve = new Cve();
                cve.setCveId(request.getParameter("cveId"));
                cve.setSourceIdentifier(request.getParameter("sourceIdentifier"));
                cve.setPublished(request.getParameter("published"));
                cve.setLastModified(request.getParameter("lastModified"));
                cve.setVulnStatus(request.getParameter("vulnStatus"));
                cve.setMetrics(request.getParameter("metrics"));
                cveDAO.insertCve(cve);
                break;

            case "/updateCveReference":
                // Aggiorna il riferimento alla CVE di uno specifico malware
                String malwareId = request.getParameter("malwareId");
                String newCveReference = request.getParameter("cveReference");
                malwareDAO.updateCVEReference(malwareId, newCveReference);
                break;

            case "/updateBaseScore":
                // Aggiorna la gravità (CVSS, baseScose) di una specifica CVE
                String cveIdToUpdate = request.getParameter("cveId");
                double newScore = Double.parseDouble(request.getParameter("newBaseScore"));
                cveDAO.updateBaseScore(cveIdToUpdate, newScore);
                break;

            case "/deleteMalware":
                // Elimina un malware, specificando l'ID generato da MongoDB
                String malwareIdToDelete = request.getParameter("malwareId");
                malwareDAO.deleteMalware(malwareIdToDelete);
                break;

            case "/deleteCve":
                // Elimina una CVE, specificando l'ID della CVE (nel formato standard CVE-2000-1234)
                String cveIdToDelete = request.getParameter("cveId");
                cveDAO.deleteCve(cveIdToDelete);
                break;

            case "/analyzeIp":
                // Esegui l'analisi di un indirizzo IP attraverso l'engine della piattaforma VirusTotal.
                // Il risultato sarà visualizzato come report in formato JSON.
                String ip = request.getParameter("ipAddress");
                String ipReportJson = VirusTotalAnalyzer.analyzeIp(ip);
                request.setAttribute("ipReport", ipReportJson);
                break;

            case "/analyzeFile":
                // Esegui l'analisi di un file sospetto attraverso l'engine della piattaforma VirusTotal.
                // Il risultato sarà visualizzato come report in formato JSON.
                Part filePart = request.getPart("fileUpload");
                InputStream fileStream = filePart.getInputStream();
                String fileReportJson = VirusTotalAnalyzer.analyzeFile(fileStream);
                request.setAttribute("fileReport", fileReportJson);
                break;

            default:
                break;
        }

        malwareDAO.close();
        cveDAO.close();

        path = "/index.jsp";
        RequestDispatcher rd = request.getRequestDispatcher(path);
        rd.forward(request,response);
    }
}
