import pytest
from experiments.benchmark_mapping_validity import (
    calculate_metrics,
    compute_keyword_overlap,
    compute_tf_idf_similarity,
    compute_hybrid_similarity,
    run_mapping_evaluation
)

def test_hand_calculated_metric_vectors():
    """
    Validates precision, recall, F1, FPR, and accuracy against known hand-calculated matrices.
    """
    # Case A: Balanced Matrix (TP=10, FP=2, TN=8, FN=0)
    # Total = 20
    # Precision = 10 / (10 + 2) = 10/12 = 0.8333
    # Recall = 10 / (10 + 0) = 1.0000
    # F1 = 2 * (10/12 * 1) / (10/12 + 1) = 20/22 = 0.9091
    # Accuracy = (10 + 8) / 20 = 18/20 = 0.9000
    # FPR = 2 / (2 + 8) = 2/10 = 0.2000
    # FNR = 0 / (0 + 10) = 0.0000
    mA = calculate_metrics(tp=10, fp=2, tn=8, fn=0)
    assert mA.precision == 0.8333
    assert mA.recall == 1.0
    assert mA.f1 == 0.9091
    assert mA.accuracy == 0.9
    assert mA.fpr == 0.2
    assert mA.fnr == 0.0
    assert mA.total == 20

    # Case B: All False Negatives (TP=0, FP=0, TN=10, FN=10)
    # Total = 20
    # Precision = 0.0 (no positive predictions)
    # Recall = 0 / 10 = 0.0
    # F1 = 0.0
    # Accuracy = 10 / 20 = 0.5000
    # FPR = 0 / 10 = 0.0000
    # FNR = 10 / 10 = 1.0000
    mB = calculate_metrics(tp=0, fp=0, tn=10, fn=10)
    assert mB.precision == 0.0
    assert mB.recall == 0.0
    assert mB.f1 == 0.0
    assert mB.accuracy == 0.5
    assert mB.fpr == 0.0
    assert mB.fnr == 1.0


def test_zero_division_guardrails():
    """
    Ensures empty or edge matrices do not trigger ZeroDivisionError.
    """
    # Zero Total
    m0 = calculate_metrics(tp=0, fp=0, tn=0, fn=0)
    assert m0.precision == 0.0
    assert m0.recall == 0.0
    assert m0.f1 == 0.0
    assert m0.accuracy == 0.0
    assert m0.total == 0

    # Zero Positives Predicted (FP=0, TP=0)
    m_no_pos = calculate_metrics(tp=0, fp=0, tn=5, fn=0)
    assert m_no_pos.precision == 0.0
    assert m_no_pos.accuracy == 1.0


def test_similarity_function_bounds():
    """
    Validates that similarity functions return values strictly bounded in [0.0, 1.0].
    """
    text1 = "Authentication account lockout after 5 consecutive failed attempts"
    text2 = "Enforces account lockout on invalid logon attempts"
    unrelated = "Cryptographic key rotation and hardware security modules"

    corpus = [text1, text2, unrelated]

    sim_related = compute_tf_idf_similarity(text1, text2, corpus)
    sim_unrelated = compute_tf_idf_similarity(text1, unrelated, corpus)
    overlap_related = compute_keyword_overlap(text1, text2)
    hybrid_related = compute_hybrid_similarity(text1, text2, corpus)
    hybrid_unrelated = compute_hybrid_similarity(text1, unrelated, corpus)

    assert 0.0 <= sim_related <= 1.0
    assert 0.0 <= sim_unrelated <= 1.0
    assert 0.0 <= overlap_related <= 1.0
    assert 0.0 <= hybrid_related <= 1.0
    assert 0.0 <= hybrid_unrelated <= 1.0

    assert sim_related > sim_unrelated
    assert hybrid_related > hybrid_unrelated


def test_hybrid_matcher_superiority_on_unseen_holdout():
    """
    Validates that the Curated GRC Lexicon Hybrid Matcher achieves strictly superior
    recall and F1 on the unseen evaluation holdout set compared to classical TF-IDF,
    without inducing false positives (FPR must remain 0.0).
    """
    results = run_mapping_evaluation()
    eval_tf = results["eval_holdout_results"]["tfidf"]
    eval_hy = results["eval_holdout_results"]["hybrid"]

    # Hybrid must achieve higher recall and F1 on holdout
    assert eval_hy["Recall"] > eval_tf["Recall"]
    assert eval_hy["F1"] > eval_tf["F1"]
    assert eval_hy["Accuracy"] > eval_tf["Accuracy"]

    # Hybrid must maintain zero false positives
    assert eval_hy["FP"] == 0
    assert eval_hy["FPR"] == 0.0
    assert eval_hy["Precision"] == 1.0


def test_run_mapping_evaluation_structure():
    """
    Validates that the full mapping evaluation returns valid schema, metrics, and breakdowns.
    """
    results = run_mapping_evaluation()
    assert "dataset_summary" in results
    assert "dev_results" in results
    assert "eval_holdout_results" in results
    assert "framework_breakdown_tfidf" in results
    assert "framework_breakdown_hybrid" in results
    assert "domain_breakdown_tfidf" in results
    assert "domain_breakdown_hybrid" in results
    assert results["dataset_summary"]["total_samples"] == 24
    assert "hybrid" in results["dev_results"]
    assert "hybrid" in results["eval_holdout_results"]
