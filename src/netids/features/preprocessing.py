"""Preprocessing for flow_features_v0.1.

The CTU-13 adapter already applies log1p.
Do not apply logarithmic transformation twice.
"""

import numpy as np

from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.exceptions import NotFittedError

from netids.features.schema import (
    FEATURE_COLUMNS,
    validate_feature_matrix,
)


class FeatureContractTransformer(BaseEstimator, TransformerMixin):
    """Validate model inputs at training and inference."""

    def fit(self, X, y=None):
        validate_feature_matrix(X)
        self.n_features_in_ = len(FEATURE_COLUMNS)
        return self

    def transform(self, X):
        if not hasattr(self, "n_features_in_"):
            raise NotFittedError(
                "FeatureContractTransformer is not fitted"
            )

        return validate_feature_matrix(X)

    def get_feature_names_out(self, input_features=None):
        return np.asarray(FEATURE_COLUMNS, dtype=object)


"""
    Hàm fit() xác nhận dữ liệu đầu vào tuân thủ schema. Hàm transform() kiểm tra lại dữ liệu khi mô hình dự đoán, đồng thời đưa các cột về đúng thứ tự.
    Lưu ý: Transformer này không học tham số chuẩn hóa. Việc chuẩn hóa bằng StandardScaler sẽ được quản lý ở pipeline mô hình.
"""