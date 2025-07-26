<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<html>
    <head>
        <title>Cybersecurity Dashboard</title>
        <style>
            body { font-family: Arial; margin: 30px; }
            h2 { color: #333; }
            form { margin-bottom: 20px; padding: 15px; border: 1px solid #ccc; }
            input, select { margin: 5px; padding: 6px; width: 250px; }
            table { border-collapse: collapse; width: 100%; margin-top: 20px; }
            th, td { border: 1px solid #aaa; padding: 8px; text-align: left; }
            th { background-color: #f0f0f0; }
            .flex-container {
                display: flex;
                gap: 40px;
                margin-bottom: 30px;
            }
            .flex-container form {
                border: 1px solid #ccc;
                padding: 15px;
                flex: 1;
            }
            pre.json-output {
                background-color: #f4f4f4;
                padding: 10px;
                border: 1px solid #ccc;
                overflow-x: auto;
                white-space: pre-wrap;
                font-family: monospace;
                margin-bottom: 20px;
            }

        </style>
    </head>
    <body>

    <h2>Analisi VirusTotal</h2>

    <div class="flex-container">
        <!-- FORM: Analisi indirizzo IP tramite l'API di VirusTotal -->
        <form action="${pageContext.request.contextPath}/UserInterfaceDBServlet/analyzeIp" method="post">
            <h3>Analizza un IP</h3>
            <input type="text" name="ipAddress" placeholder="Inserisci un IP" required />
            <input type="submit" value="Analizza IP" />
        </form>

        <!-- FORM: Analisi file sospetto tramite l'API di VirusTotal -->
        <form action="${pageContext.request.contextPath}/UserInterfaceDBServlet/analyzeFile" method="post" enctype="multipart/form-data">
            <h3>Carica un file per analisi</h3>
            <input type="file" name="fileUpload" required />
            <input type="submit" value="Analizza File" />
        </form>
    </div>

    <!-- Mostra i risultati dell'analisi di VirusTotal in formato JSON -->
    <c:if test="${not empty ipReport}">
        <h3>Risultato Analisi IP</h3>
        <pre class="json-output">${ipReport}</pre>
    </c:if>

    <!-- Mostra i risultati dell'analisi di VirusTotal in formato JSON -->
    <c:if test="${not empty fileReport}">
        <h3>Risultato Analisi File</h3>
        <pre class="json-output">${fileReport}</pre>
    </c:if>


    <h2>Operazioni Malware & CVE</h2>

        <!-- CREA MALWARE -->
        <form action="${pageContext.request.contextPath}/UserInterfaceDBServlet/createMalware" method="post">
            <h3>Crea un nuovo Malware</h3>
            <input type="hidden" name="action" value="createMalware" />
            <input type="text" name="startTime" placeholder="Start Time" required />
            <input type="text" name="lastTime" placeholder="Last Time" required />
            <input type="text" name="attackCategory" placeholder="Attack Category" />
            <input type="text" name="attackSubcategory" placeholder="Attack Subcategory" />
            <input type="text" name="protocol" placeholder="Protocol" />
            <input type="text" name="sourceIP" placeholder="Source IP" />
            <input type="text" name="sourcePort" placeholder="Source Port" />
            <input type="text" name="destinationIP" placeholder="Destination IP" />
            <input type="text" name="destinationPort" placeholder="Destination Port" />
            <input type="text" name="attackName" placeholder="Attack Name" />
            <input type="text" name="attackReference" placeholder="Attack Reference (es. CVE 2007-0015)" />
            <input type="submit" value="Crea Malware" />
        </form>

        <!-- CREA CVE -->
        <form action="${pageContext.request.contextPath}/UserInterfaceDBServlet/createCve" method="post">
            <h3>Crea una nuova CVE</h3>
            <input type="hidden" name="action" value="createCve" />
            <input type="text" name="cveId" placeholder="CVE ID (es. CVE-2007-0015)" required />
            <input type="text" name="sourceIdentifier" placeholder="Source Identifier" />
            <input type="text" name="published" placeholder="Published Date" />
            <input type="text" name="lastModified" placeholder="Last Modified Date" />
            <input type="text" name="vulnStatus" placeholder="Vulnerability Status" />
            <input type="text" name="metrics" placeholder="Metrics" />
            <input type="submit" value="Crea CVE" />
        </form>

        <!-- TROVA MALWARE PER CVE -->
        <form action="${pageContext.request.contextPath}/UserInterfaceDBServlet/findMalwareByCve" method="get">
            <h3>Trova Malware per CVE</h3>
            <input type="hidden" name="action" value="findMalwareByCve" />
            <input type="text" name="cveId" placeholder="CVE ID (es. CVE-2007-0015)" required />
            <input type="submit" value="Cerca Malware" />
        </form>

        <!-- TROVA MALWARE PER CATEGORIA -->
        <form action="${pageContext.request.contextPath}/UserInterfaceDBServlet/findMalwareByCategory" method="get">
            <h3>Trova Malware per categoria</h3>
            <input type="hidden" name="action" value="findMalwareByCategory" />
            <input type="text" name="category" placeholder="Category (Es. Exploits, DoS, ...)" required />
            <input type="submit" value="Cerca Malware" />
        </form>

        <!-- TROVA CVE PER GRAVITA' (BASESCORE) -->
        <form action="${pageContext.request.contextPath}/UserInterfaceDBServlet/findCveBySeverity" method="get">
            <h3>Trova CVE per gravità minima</h3>
            <input type="hidden" name="action" value="findCveBySeverity" />
            <input type="text" name="minSeverity" placeholder="Min Base Score (es. 9.0)" required />
            <input type="submit" value="Cerca CVE" />
        </form>

        <!-- AGGIORNA CVE IN MALWARE -->
        <form action="${pageContext.request.contextPath}/UserInterfaceDBServlet/updateCveReference" method="post">
            <h3>Aggiorna CVE di un Malware</h3>
            <input type="hidden" name="action" value="updateCveReference" />
            <input type="text" name="malwareId" placeholder="Malware ID" required />
            <input type="text" name="cveReference" placeholder="Nuova Attack Reference" required />
            <input type="submit" value="Aggiorna" />
        </form>

        <!-- AGGIORNA GRAVITA' (BASESCORE) IN CVE -->
        <form action="${pageContext.request.contextPath}/UserInterfaceDBServlet/updateBaseScore" method="post">
            <h3>Aggiorna la Base Score di una CVE</h3>
            <input type="hidden" name="action" value="updateBaseScore" />
            <input type="text" name="cveId" placeholder="CVE ID" required />
            <input type="text" name="newBaseScore" placeholder="Nuova Base Score" required />
            <input type="submit" value="Aggiorna" />
        </form>

        <!-- ELIMINA MALWARE -->
        <form action="${pageContext.request.contextPath}/UserInterfaceDBServlet/deleteMalware" method="post">
            <h3>Elimina un Malware</h3>
            <input type="hidden" name="action" value="deleteMalware" />
            <input type="text" name="malwareId" placeholder="Malware ID" required />
            <input type="submit" value="Elimina Malware" />
        </form>

        <!-- ELIMINA CVE -->
        <form action="${pageContext.request.contextPath}/UserInterfaceDBServlet/deleteCve" method="post">
            <h3>Elimina una CVE</h3>
            <input type="hidden" name="action" value="deleteCve" />
            <input type="text" name="cveId" placeholder="CVE ID" required />
            <input type="submit" value="Elimina CVE" />
        </form>

        <!-- JOIN: TROVA CVE CON GRAVITA' MAGGIORE O UGUALE DEL VALORE DATO,
        CON RELATIVI MALWARE ASSOCIATI -->
        <form action="${pageContext.request.contextPath}/UserInterfaceDBServlet/getHighSeverityCVEsWithMalware" method="get">
            <h3>Trova CVE per gravità minima e Malware associati</h3>
            <input type="hidden" name="action" value="getHighSeverityCVEsWithMalware" />
            <input type="text" name="threshold" placeholder="Min Base Score (es. 9.0)" required />
            <input type="submit" value="Cerca CVE e Malware" />
        </form>

        <!-- TABELLA RISULTATI MALWARE -->
        <c:if test="${not empty malwareList}">
            <h3>Risultati Malware</h3>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Start Time</th>
                    <th>Last Time</th>
                    <th>Attack Category</th>
                    <th>Attack Subcategory</th>
                    <th>Protocol</th>
                    <th>Source IP</th>
                    <th>Source Port</th>
                    <th>Destination IP</th>
                    <th>Destination Port</th>
                    <th>Attack Name</th>
                    <th>Attack Reference</th>
                </tr>
                <c:forEach var="doc" items="${malwareList}">
                    <tr>
                        <td><c:out value="${doc['_id']}"/></td>
                        <td><c:out value="${doc['Start time']}" /></td>
                        <td><c:out value="${doc['Last time']}" /></td>
                        <td><c:out value="${doc['Attack category']}" /></td>
                        <td><c:out value="${doc['Attack subcategory']}" /></td>
                        <td><c:out value="${doc['Protocol']}" /></td>
                        <td><c:out value="${doc['Source IP']}" /></td>
                        <td><c:out value="${doc['Source Port']}" /></td>
                        <td><c:out value="${doc['Destination IP']}" /></td>
                        <td><c:out value="${doc['Destination Port']}" /></td>
                        <td><c:out value="${doc['Attack Name']}" /></td>
                        <td><c:out value="${doc['Attack Reference']}" /></td>
                    </tr>
                </c:forEach>
            </table>
        </c:if>

        <!-- TABELLA RISULTATI CVE -->
        <c:if test="${not empty cveList}">
            <h3>Risultati CVE</h3>
            <table>
                <tr>
                    <th>CVE ID</th>
                    <th>Source</th>
                    <th>Published</th>
                    <th>Last Modified</th>
                    <th>Status</th>
                    <th>Base Score</th>
                    <th>Description (EN)</th>
                </tr>
                <c:forEach var="cveDoc" items="${cveList}">
                    <tr>
                        <c:set var="cve" value="${cveDoc['cve']}" />
                        <td><c:out value="${cve.id}" /></td>
                        <td><c:out value="${cve.sourceIdentifier}" /></td>
                        <td><c:out value="${cve.published}" /></td>
                        <td><c:out value="${cve.lastModified}" /></td>
                        <td><c:out value="${cve.vulnStatus}" /></td>
                        <td><c:out value="${cve.metrics.cvssMetricV2[0].cvssData.baseScore}" /></td>
                        <td>
                            <c:forEach var="desc" items="${cve.descriptions}">
                                <c:if test="${desc.lang == 'en'}">
                                    <c:out value="${desc.value}" />

                                </c:if>
                            </c:forEach>
                        </td>
                    </tr>
                </c:forEach>
            </table>
        </c:if>

        <!-- TABELLA RISULTATI JOIN CVE & MALWARE -->
        <c:if test="${not empty joinedResults}">
            <h3>JOIN: CVE con malware associati (solo ID)</h3>
            <table>
                <tr>
                    <th>CVE ID</th>
                    <th>Base Score</th>
                    <th>Description (EN)</th>
                    <th>Malware IDs</th>
                </tr>
                <c:forEach var="cveDoc" items="${joinedResults}">
                    <c:set var="cve" value="${cveDoc.cve}" />
                    <tr>
                        <td><c:out value="${cve.id}" /></td>
                        <td><c:out value="${cve.metrics.cvssMetricV2[0].cvssData.baseScore}" /></td>
                        <td>
                            <c:forEach var="desc" items="${cve.descriptions}">
                                <c:if test="${desc.lang == 'en'}">
                                    <c:out value="${desc.value}" />
                                </c:if>
                            </c:forEach>
                        </td>
                        <td>
                            <c:forEach var="malId" items="${cveDoc.malwareIds}" varStatus="loop">
                                <c:out value="${malId}" />
                                <c:if test="${!loop.last}">, </c:if>
                            </c:forEach>
                        </td>
                    </tr>
                </c:forEach>
            </table>
        </c:if>

    </body>
</html>
