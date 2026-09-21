import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

public class DebugParse {
    public static void main(String[] args) {
        String[] inputs = {
            "<head>content</head><p>safe</p>",
            "<script>alert(1); <!--",
            "<scr script >alert(1)</scr script >",
            "java script:alert(1)",
        };
        for (String input : inputs) {
            Document doc = Jsoup.parse(input);
            System.out.println("Input: [" + input + "]");
            System.out.println("Body HTML: [" + doc.body().html() + "]");
            System.out.println("Doc HTML: [" + doc.html() + "]");
            Elements heads = doc.select("head");
            System.out.println("Heads found: " + heads.size());
            for (Element head : heads) {
                System.out.println("Head children count: " + head.children().size());
                System.out.println("Head child elements: " + head.children());
                System.out.println("Head own text: [" + head.ownText() + "]");
            }
            System.out.println("Body child elements: " + doc.body().children().size());
            System.out.println("Body children:");
            for (Element child : doc.body().children()) {
                System.out.println("  [" + child.tagName() + "] text=[" + child.ownText() + "]");
            }
            System.out.println("---");
        }
    }
}
