import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.AnnotationExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;

/**
 * JavaParser (Apache-2.0) AST & symbol extractor for LOTUS ProgramFacts IR.
 * Run with: java -cp /path/to/javaparser-core.jar scripts/adapters/JavaParserFacts.java <file1> [file2 ...]
 */
public class JavaParserFacts {
    private static final Set<String> AUTH_ANNOTATIONS = Set.of(
        "PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed", "PermitAll"
    );
    private static final Set<String> ROUTE_ANNOTATIONS = Set.of(
        "RequestMapping", "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping",
        "GET", "POST", "PUT", "DELETE", "Path"
    );
    private static final Map<String, String> SINK_METHODS = Map.ofEntries(
        Map.entry("exec", "OS command execution sink"),
        Map.entry("executeQuery", "SQL statement query sink"),
        Map.entry("executeUpdate", "SQL statement update sink"),
        Map.entry("execute", "SQL/command execute sink"),
        Map.entry("readObject", "Unsafe Java deserialization sink"),
        Map.entry("eval", "Dynamic script evaluation sink"),
        Map.entry("readString", "Filesystem read sink"),
        Map.entry("newInstance", "XML/reflection factory instantiation sink")
    );

    private static String stableId(String input) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] digest = md.digest(input.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10; i++) sb.append(String.format("%02x", digest[i]));
        return sb.toString();
    }

    private static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    public static void main(String[] args) throws Exception {
        List<String> symbols = new ArrayList<>();
        List<String> facts = new ArrayList<>();
        List<String> edges = new ArrayList<>();
        List<String> errors = new ArrayList<>();

        for (int i = 0; i + 1 < args.length; i += 2) {
            String logicalPath = args[i];
            String diskPath = args[i + 1];
            try {
                String code = Files.readString(Path.of(diskPath), StandardCharsets.UTF_8);
                CompilationUnit cu = StaticJavaParser.parse(code);

                for (ClassOrInterfaceDeclaration cls : cu.findAll(ClassOrInterfaceDeclaration.class)) {
                    String cname = cls.getNameAsString();
                    int cLine = cls.getBegin().map(p -> p.line).orElse(1);
                    int cEnd = cls.getEnd().map(p -> p.line).orElse(cLine);
                    String cId = stableId("jp|class|" + logicalPath + "|" + cname + "|" + cLine);
                    symbols.add("{\"id\":\"" + cId + "\",\"name\":\"" + esc(cname) + "\",\"qualifiedName\":\"" + esc(cname)
                        + "\",\"kind\":\"class\",\"language\":\"java\",\"file\":\"" + esc(logicalPath)
                        + "\",\"line\":" + cLine + ",\"endLine\":" + cEnd + ",\"modifiers\":[]}");

                    for (MethodDeclaration m : cls.getMethods()) {
                        String mname = m.getNameAsString();
                        String qname = cname + "." + mname;
                        int mLine = m.getBegin().map(p -> p.line).orElse(1);
                        int mEnd = m.getEnd().map(p -> p.line).orElse(mLine);
                        String mId = stableId("jp|method|" + logicalPath + "|" + qname + "|" + mLine);

                        List<String> anns = new ArrayList<>();
                        boolean hasAuth = false;
                        boolean isRoute = false;
                        for (AnnotationExpr a : m.getAnnotations()) {
                            String an = a.getNameAsString();
                            anns.add(an);
                            if (AUTH_ANNOTATIONS.contains(an)) hasAuth = true;
                            if (ROUTE_ANNOTATIONS.contains(an)) isRoute = true;
                        }
                        String vis = m.isPublic() ? "public" : (m.isProtected() ? "protected" : "private");
                        StringBuilder modJson = new StringBuilder("[");
                        for (int k = 0; k < anns.size(); k++) {
                            if (k > 0) modJson.append(",");
                            modJson.append("\"").append(esc(anns.get(k))).append("\"");
                        }
                        modJson.append("]");

                        symbols.add("{\"id\":\"" + mId + "\",\"name\":\"" + esc(mname) + "\",\"qualifiedName\":\"" + esc(qname)
                            + "\",\"kind\":\"method\",\"language\":\"java\",\"file\":\"" + esc(logicalPath)
                            + "\",\"line\":" + mLine + ",\"endLine\":" + mEnd + ",\"visibility\":\"" + vis
                            + "\",\"modifiers\":" + modJson + "}");

                        if (isRoute || m.isPublic()) {
                            String fId = stableId("jp|entry|" + logicalPath + "|" + qname + "|" + mLine);
                            facts.add("{\"id\":\"" + fId + "\",\"kind\":\"entry_point\",\"adapter\":\"javaparser\",\"file\":\""
                                + esc(logicalPath) + "\",\"line\":" + mLine + ",\"symbol\":\"" + esc(qname)
                                + "\",\"summary\":\"" + esc("JavaParser " + (isRoute ? "route " : "public ") + "method " + qname)
                                + "\",\"confidence\":" + (isRoute ? "0.92" : "0.78") + ",\"attributes\":{\"isRoute\":" + isRoute + "}}");
                        }

                        if (hasAuth) {
                            String aId = stableId("jp|auth|" + logicalPath + "|" + qname + "|" + mLine);
                            facts.add("{\"id\":\"" + aId + "\",\"kind\":\"auth_guard\",\"adapter\":\"javaparser\",\"file\":\""
                                + esc(logicalPath) + "\",\"line\":" + mLine + ",\"symbol\":\"" + esc(qname)
                                + "\",\"summary\":\"" + esc("JavaParser auth annotation on " + qname)
                                + "\",\"confidence\":0.94,\"attributes\":{\"annotations\":" + modJson + "}}");
                        }

                        for (MethodCallExpr call : m.findAll(MethodCallExpr.class)) {
                            String callName = call.getNameAsString();
                            String scope = call.getScope().map(Object::toString).orElse("");
                            String callee = scope.isEmpty() ? callName : scope + "." + callName;
                            int callLine = call.getBegin().map(p -> p.line).orElse(mLine);

                            edges.add("{\"kind\":\"calls\",\"from\":\"" + mId + "\",\"to\":\"" + esc(callee)
                                + "\",\"file\":\"" + esc(logicalPath) + "\",\"line\":" + callLine + "}");

                            if (SINK_METHODS.containsKey(callName)) {
                                // Only flag newInstance when XML/DocumentBuilder/SAX/Transformer related
                                if (callName.equals("newInstance") && !scope.contains("DocumentBuilder") && !scope.contains("SAXParser") && !scope.contains("Transformer")) {
                                    continue;
                                }
                                String sId = stableId("jp|sink|" + logicalPath + "|" + qname + "|" + callName + "|" + callLine);
                                facts.add("{\"id\":\"" + sId + "\",\"kind\":\"dangerous_sink\",\"adapter\":\"javaparser\",\"file\":\""
                                    + esc(logicalPath) + "\",\"line\":" + callLine + ",\"symbol\":\"" + esc(qname)
                                    + "\",\"summary\":\"" + esc(SINK_METHODS.get(callName) + " (" + callee + ") in " + qname)
                                    + "\",\"confidence\":0.88,\"attributes\":{\"callee\":\"" + esc(callee) + "\"}}");
                            }
                        }

                        for (ObjectCreationExpr ctor : m.findAll(ObjectCreationExpr.class)) {
                            String typeName = ctor.getTypeAsString();
                            if (typeName.equals("ProcessBuilder") || typeName.equals("ObjectInputStream")) {
                                int ctorLine = ctor.getBegin().map(p -> p.line).orElse(mLine);
                                String sId = stableId("jp|ctor|" + logicalPath + "|" + qname + "|" + typeName + "|" + ctorLine);
                                facts.add("{\"id\":\"" + sId + "\",\"kind\":\"dangerous_sink\",\"adapter\":\"javaparser\",\"file\":\""
                                    + esc(logicalPath) + "\",\"line\":" + ctorLine + ",\"symbol\":\"" + esc(qname)
                                    + "\",\"summary\":\"" + esc("Dangerous instantiation new " + typeName + "() in " + qname)
                                    + "\",\"confidence\":0.9,\"attributes\":{\"constructor\":\"" + esc(typeName) + "\"}}");
                            }
                        }
                    }
                }
            } catch (Exception ex) {
                errors.add("\"" + esc(logicalPath + ": " + ex.getMessage()) + "\"");
            }
        }

        System.out.println("{\"adapter\":\"javaparser\",\"symbols\":[" + String.join(",", symbols)
            + "],\"facts\":[" + String.join(",", facts)
            + "],\"edges\":[" + String.join(",", edges)
            + "],\"errors\":[" + String.join(",", errors) + "]}");
    }
}
