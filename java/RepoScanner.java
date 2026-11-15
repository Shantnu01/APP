package repoguard.scanner;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * RepoGuard Maven POM Dependency Analyzer
 *
 * Implements hardened, read-only parsing of pom.xml manifests to identify
 * groupId, artifactId, and versions with basic property placeholder resolution.
 * Strictly operates in a secure sandbox mode with external entities disabled.
 *
 * Authors: Shantnu, Arya Agrawal, Raiyan Kamal
 * Course: Advanced Programming Practices | Section: H2 | Dr. Rajesh Kannan
 */
public final class RepoScanner {

    private static String getDirectChildText(Element parent, String tagName) {
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                String nodeName = child.getLocalName() != null ? child.getLocalName() : child.getNodeName();
                if (tagName.equalsIgnoreCase(nodeName)) {
                    return child.getTextContent().trim();
                }
            }
        }
        return "";
    }

    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: RepoScanner <path-to-pom.xml>");
            System.exit(2);
        }

        File pomFile = new File(args[0]);
        if (!pomFile.exists() || !pomFile.isFile()) {
            System.err.println("Target POM file not found: " + args[0]);
            System.exit(1);
        }

        try (InputStream in = new FileInputStream(pomFile)) {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");

            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(in);

            // Step 1: Extract <properties> into a lookup table for variable substitution
            Map<String, String> propertiesMap = new HashMap<>();
            NodeList propsNodes = doc.getElementsByTagNameNS("*", "properties");
            for (int i = 0; i < propsNodes.getLength(); i++) {
                Node pNode = propsNodes.item(i);
                if (pNode.getNodeType() == Node.ELEMENT_NODE) {
                    NodeList pChildren = pNode.getChildNodes();
                    for (int j = 0; j < pChildren.getLength(); j++) {
                        Node prop = pChildren.item(j);
                        if (prop.getNodeType() == Node.ELEMENT_NODE) {
                            String key = prop.getLocalName() != null ? prop.getLocalName() : prop.getNodeName();
                            propertiesMap.put(key, prop.getTextContent().trim());
                        }
                    }
                }
            }

            // Step 2: Parse <dependencies> under <project>
            NodeList depContainers = doc.getElementsByTagNameNS("*", "dependencies");
            List<String> outputRows = new ArrayList<>();

            for (int i = 0; i < depContainers.getLength(); i++) {
                Node container = depContainers.item(i);
                Node parent = container.getParentNode();
                if (parent == null) continue;
                String parentName = parent.getLocalName() != null ? parent.getLocalName() : parent.getNodeName();
                if (!"project".equalsIgnoreCase(parentName)) {
                    // Ignore dependencyManagement or plugin dependencies for direct inventory
                    continue;
                }

                NodeList depNodes = container.getChildNodes();
                for (int j = 0; j < depNodes.getLength(); j++) {
                    Node dNode = depNodes.item(j);
                    if (dNode.getNodeType() != Node.ELEMENT_NODE) continue;

                    String dName = dNode.getLocalName() != null ? dNode.getLocalName() : dNode.getNodeName();
                    if (!"dependency".equalsIgnoreCase(dName)) continue;

                    Element depElem = (Element) dNode;
                    String group = getDirectChildText(depElem, "groupId");
                    String artifact = getDirectChildText(depElem, "artifactId");
                    String version = getDirectChildText(depElem, "version");

                    // Resolve ${property} if present
                    if (version.startsWith("${") && version.endsWith("}")) {
                        String propKey = version.substring(2, version.length() - 1).trim();
                        if (propertiesMap.containsKey(propKey)) {
                            version = propertiesMap.get(propKey);
                        }
                    }

                    if (!group.isEmpty() && !artifact.isEmpty() && !version.isEmpty() && !version.contains("$")) {
                        outputRows.add(group + "\t" + artifact + "\t" + version);
                    }
                }
            }

            for (String row : outputRows) {
                System.out.println(row);
            }

        } catch (Exception ex) {
            System.err.println("XML Parsing Exception: " + ex.getMessage());
            System.exit(1);
        }
    }
}
