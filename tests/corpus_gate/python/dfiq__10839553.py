import unittest

import yaml

from core import database_arango
from core.schemas.dfiq import (
    DFIQApproach,
    DFIQFacet,
    DFIQQuestion,
    DFIQScenario,
    DFIQType,
    read_from_data_directory,
)


class DFIQTest(unittest.TestCase):
    def setUp(self) -> None:
        database_arango.db.connect(database="yeti_test")
        database_arango.db.truncate()

    def test_dfiq_scenario(self) -> None:
        with open("tests/dfiq_test_data/S1003.yaml", "r") as f:
            yaml_string = f.read()

        result = DFIQScenario.from_yaml(yaml_string).save()
        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "scenario1")
        self.assertEqual(result.dfiq_version, "1.1.0")
        self.assertEqual(str(result.uuid), "2ee16263-56f8-49a5-9b33-d1a2dd8b829c")
        self.assertEqual(result.description, "Long description 1\n")
        self.assertEqual(result.type, DFIQType.scenario)
        self.assertEqual(result.dfiq_tags, ["Tag1", "Tag2", "Tag3"])

    def test_dfiq_scenario_no_id(self) -> None:
        with open("tests/dfiq_test_data/DFIQ_Scenario_no_id.yaml", "r") as f:
            yaml_string = f.read()

        result = DFIQScenario.from_yaml(yaml_string).save()
        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "scenario1")
        self.assertEqual(result.dfiq_version, "1.1.0")
        self.assertEqual(str(result.uuid), "2ee16263-56f8-49a5-9b33-d1a2dd8b829c")
        self.assertEqual(result.description, "Long description 1\n")
        self.assertEqual(result.type, DFIQType.scenario)
        self.assertEqual(result.dfiq_tags, ["Tag1", "Tag2", "Tag3"])

    def test_dfiq_facet(self) -> None:
        with open("tests/dfiq_test_data/F1005.yaml", "r") as f:
            yaml_string = f.read()

        result = DFIQFacet.from_yaml(yaml_string).save()

        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "facet1")
        self.assertEqual(result.description, "Long description of facet1\n")
        self.assertEqual(result.dfiq_id, "F1005")
        self.assertEqual(result.dfiq_version, "1.1.0")
        self.assertEqual(str(result.uuid), "b2bab31f-1670-4297-8cb1-685747a13468")
        self.assertEqual(result.dfiq_tags, ["Web Browser"])
        self.assertEqual(result.parent_ids, ["S1003"])
        self.assertEqual(result.type, DFIQType.facet)

    def test_dfiq_question(self) -> None:
        with open("tests/dfiq_test_data/Q1020.yaml", "r") as f:
            yaml_string = f.read()

        result = DFIQQuestion.from_yaml(yaml_string).save()

        self.assertIsNotNone(result.id)
        self.assertIsNotNone(result.created)
        self.assertEqual(result.name, "What is a question?")
        self.assertEqual(result.description, None)
        self.assertEqual(str(result.uuid), "bd46ce6e-c933-46e5-960c-36945aaef401")
        self.assertEqual(result.dfiq_id, "Q1020")
        self.assertEqual(result.dfiq_version, "1.1.0")
        self.assertEqual(result.dfiq_tags, ["Web Browser"])
        self.assertEqual(result.parent_ids, ["F1005"])
        self.assertEqual(result.type, DFIQType.question)

    def test_dfiq_conversion_to_yaml(self) -> None:
        self.maxDiff = None
        type_map = [
            (DFIQScenario, "tests/dfiq_test_data/S1003.yaml"),
            (DFIQFacet, "tests/dfiq_test_data/F1005.yaml"),
            (DFIQQuestion, "tests/dfiq_test_data/Q1020.yaml"),
        ]

        for type_, file_path in type_map:
            with open(file_path, "r") as f:
                yaml_string = f.read()

            result = type_.from_yaml(yaml_string).save()

            expected_yaml_string = yaml.dump(
                yaml.safe_load(yaml_string),
                default_flow_style=False,
                sort_keys=True,
                explicit_start=True,
                indent=2,
            )
            result_yaml_string = result.to_yaml(sort_keys=True)
            self.assertEqual(expected_yaml_string, result_yaml_string)

    def test_read_from_data_directory(self) -> None:
        dfiq_addition = read_from_data_directory("tests/dfiq_test_data/*", "test")

        scenarios = DFIQScenario.list()
        self.assertEqual(len(list(scenarios)), 1)

        facets = DFIQFacet.list()
        self.assertEqual(len(list(facets)), 1)

        questions = DFIQQuestion.list()
        self.assertEqual(len(list(questions)), 1)

        self.assertEqual(len(dfiq_addition.dfiq), 3)
