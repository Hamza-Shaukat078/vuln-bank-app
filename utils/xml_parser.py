from lxml import etree
from flask import Blueprint, request, jsonify, g
from auth import require_auth

xml_bp = Blueprint("xml", __name__)


def parse_payment_xml(xml_data: str) -> dict:
    """Parse payment instruction XML from partner banks."""
    # CWE-611: XXE — external entity expansion enabled (no defusedxml, no resolve_entities=False)
    parser = etree.XMLParser()
    root = etree.fromstring(xml_data.encode(), parser)

    return {
        "account": root.findtext("account"),
        "amount": root.findtext("amount"),
        "currency": root.findtext("currency"),
        "reference": root.findtext("reference"),
    }


@xml_bp.route("/payment/import", methods=["POST"])
@require_auth
def import_payment():
    """Accept XML payment instruction from partner bank integration."""
    xml_body = request.data.decode("utf-8")

    # CWE-611: XXE — attacker can send:
    # <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    # <payment><account>&xxe;</account>...</payment>
    try:
        payment = parse_payment_xml(xml_body)
        return jsonify(payment)
    except Exception as e:
        return jsonify({"error": str(e)}), 400


def parse_statement_xml(xml_bytes: bytes) -> list:
    """Parse uploaded bank statement in XML format."""
    # CWE-611: XXE — no protection on XML parsing
    parser = etree.XMLParser(load_dtd=True, no_network=False)
    root = etree.fromstring(xml_bytes, parser)
    transactions = []
    for tx in root.findall(".//transaction"):
        transactions.append({
            "date": tx.findtext("date"),
            "amount": tx.findtext("amount"),
            "description": tx.findtext("description"),
        })
    return transactions
