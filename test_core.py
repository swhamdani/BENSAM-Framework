# File: tests/test_core.py

"""
This module contains unit tests for the framework's core components.
It demonstrates the use of pytest fixtures and parametrization for
clean and efficient testing.
"""
import pytest
from unittest.mock import Mock
from my_framework.core import DataPipeline

# Pytest Fixture: A reusable component for test setup
@pytest.fixture
def mock_pipeline_components():
    """
    Provides mock objects for the pipeline's interfaces.
    """
    mock_source = Mock()
    mock_source.get_data.return_value = "raw data"
    mock_processor = Mock()
    mock_processor.process_data.return_value = "processed data"
    mock_sink = Mock()
    return mock_source, mock_processor, mock_sink

def test_pipeline_runs_successfully(mock_pipeline_components):
    """
    Tests that the DataPipeline's run method orchestrates calls correctly.
    """
    mock_source, mock_processor, mock_sink = mock_pipeline_components
    pipeline = DataPipeline(mock_source, mock_processor, mock_sink)
    pipeline.run()

    # Assert that the correct methods were called
    mock_source.get_data.assert_called_once()
    mock_processor.process_data.assert_called_once_with("raw data")
    mock_sink.load_data.assert_called_once_with("processed data")

# Pytest Parametrization: Runs the same test with different inputs
@pytest.mark.parametrize("input_data, expected_output",)
def test_mock_processor_uppercase(input_data, expected_output):
    """
    A simple test to demonstrate the processor's behavior using a mock.
    """
    mock_processor = Mock()
    mock_processor.process_data.return_value = input_data.upper()
    
    result = mock_processor.process_data(input_data)
    
    assert result == expected_output