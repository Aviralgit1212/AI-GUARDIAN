from presidio_analyzer import AnalyzerEngine


class Scanner:
    """
    Detects sensitive entities in text using Microsoft Presidio.
    """

    def __init__(self):
        self.analyzer = AnalyzerEngine()

        self.entities_to_detect = [
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "CREDIT_CARD",
            "US_SSN",
            "PERSON",
        ]

    def scan(self, text: str) -> list[dict]:
        results = self.analyzer.analyze(
            text=text,
            language="en",
            entities=self.entities_to_detect,
        )

        entities = []

        for result in results:
            entities.append(
                {
                    "entity_type": result.entity_type,
                    "text": text[result.start:result.end],
                    "start": result.start,
                    "end": result.end,
                }
            )

        return entities