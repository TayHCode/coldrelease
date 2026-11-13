import importlib
import unittest

LESSON_TESTS = {
    "verify-the-right-thing": (
        "test_published_target.PublishedTargetTests.test_side_branch_or_tag_on_target_fails_real_cli_before_scan",
        "test_published_target.PublishedTargetTests.test_detached_target_head_at_private_history_fails_real_cli_before_scan",
        "test_published_target.PublishedTargetTests.test_expected_export_rejects_another_commit_or_tree_before_scan",
        "test_ship.ShipTests.test_ship_refuses_a_target_tree_swapped_after_readback",
    ),
    "secrets-and-private-data": (
        "test_fleet_cli.FleetCliScannerTests.test_fleet_commands_block_with_file_and_line_and_neutral_examples_stay_clean",
        "test_agent_reference.GrokBotReferenceTests.test_bot_name_variants_block_at_the_exact_line_and_neutral_names_stay_clean",
        "test_bare_private_repo.BarePrivateRepoNameTests.test_placeholder_owner_and_bare_name_block_in_tree_and_export_history",
    ),
    "errors-are-states": (
        "test_release_workflow.WorkflowTests.test_scanner_results_record_why_they_are_not_pass",
        "test_release_workflow.WorkflowTests.test_plan_rejects_trufflehog_without_required_flags",
        "test_check_timeout.CheckTimeoutTests.test_check_over_its_manifest_timeout_fails_export_and_a_larger_budget_passes",
    ),
    "engine-scan-only-git-visible-files": (
        "test_worktree_scope.WorktreeScopeTests.test_ignored_working_folders_are_not_scanned",
    ),
    "engine-verify-workspace-outside-git-checkout": (
        "test_release_check.AuditTests.test_verify_commands_cannot_discover_a_repository_above_the_workspace",
    ),
    "engine-incomplete-names-its-cause": (
        "test_explain_incomplete.ExplainIncompleteTests.test_subdirectory_of_another_repository_is_incomplete",
    ),
}


class ColdfixLessonTests(unittest.TestCase):
    def assert_enforced(self, lesson):
        for test_id in LESSON_TESTS[lesson]:
            module, case, method = test_id.split(".")
            found = getattr(getattr(importlib.import_module(module), case, None), method, None)
            self.assertTrue(callable(found), f"{lesson}: {test_id} no longer exists")

    def test_every_lesson_has_a_test_named_after_it(self):
        for lesson in LESSON_TESTS:
            self.assertTrue(hasattr(self, "test_" + lesson.replace("-", "_")), lesson)

    def test_verify_the_right_thing(self):
        self.assert_enforced("verify-the-right-thing")

    def test_secrets_and_private_data(self):
        self.assert_enforced("secrets-and-private-data")

    def test_errors_are_states(self):
        self.assert_enforced("errors-are-states")

    def test_engine_scan_only_git_visible_files(self):
        self.assert_enforced("engine-scan-only-git-visible-files")

    def test_engine_verify_workspace_outside_git_checkout(self):
        self.assert_enforced("engine-verify-workspace-outside-git-checkout")

    def test_engine_incomplete_names_its_cause(self):
        self.assert_enforced("engine-incomplete-names-its-cause")


if __name__ == "__main__":
    unittest.main()
