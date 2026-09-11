using System;
using System.Xml;
using System.Runtime.Serialization;

class SerializeApp {
    static void Main() {
        string xmlInput = Request.QueryString["xml"];
        string jsonInput = Request.Form["json"];

        // 漏洞 - XXE
        XmlDocument doc = new XmlDocument();
        doc.LoadXml(xmlInput);
        XmlReader reader = XmlReader.Create(xmlInput);

        // 漏洞 - 反序列化
        BinaryFormatter formatter = new BinaryFormatter();
        formatter.Deserialize(OpenRead(xmlInput));

        // 安全
        doc.LoadXml("<root><item>1</item></root>");
    }
}
