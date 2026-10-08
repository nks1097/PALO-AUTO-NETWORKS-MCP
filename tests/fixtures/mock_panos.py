"""
Mock de respostas da API XML e REST do Palo Alto PAN-OS para testes unitários.
"""

MOCK_SYSTEM_INFO_XML = """<response status="success">
    <result>
        <system>
            <hostname>PALO_AUTO_TEST</hostname>
            <ip-address>192.168.0.247</ip-address>
            <netmask>255.255.255.0</netmask>
            <default-gateway>192.168.0.254</default-gateway>
            <model>PA-VM</model>
            <serial>001122334455</serial>
            <sw-version>11.0.0</sw-version>
            <uptime>10 days, 4:12:30</uptime>
            <app-version>8635-7675</app-version>
            <threat-version>8635-7675</threat-version>
            <av-version>8635-7675</av-version>
            <wildfire-version>0</wildfire-version>
        </system>
    </result>
</response>"""

MOCK_SECURITY_RULES_REST = {
    "@status": "success",
    "@code": "19",
    "result": {
        "@total-count": "2",
        "@count": "2",
        "entry": [
            {
                "@name": "Allow-Web",
                "from": {"member": ["Trust"]},
                "to": {"member": ["Untrust"]},
                "source": {"member": ["10.0.0.0/24"]},
                "destination": {"member": ["any"]},
                "application": {"member": ["web-browsing", "ssl"]},
                "service": {"member": ["application-default"]},
                "action": "allow",
                "disabled": "no",
            },
            {
                "@name": "Deny-All",
                "from": {"member": ["any"]},
                "to": {"member": ["any"]},
                "source": {"member": ["any"]},
                "destination": {"member": ["any"]},
                "application": {"member": ["any"]},
                "service": {"member": ["any"]},
                "action": "deny",
                "disabled": "no",
            },
        ],
    },
}

MOCK_ADDRESSES_REST = {
    "@status": "success",
    "result": {
        "@total-count": "1",
        "entry": [
            {
                "@name": "SRV_DATABASE",
                "ip-netmask": "192.168.10.50/32",
                "description": "Banco de Dados Producao",
            }
        ],
    },
}
