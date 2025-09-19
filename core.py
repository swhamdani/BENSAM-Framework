# File: src/my_framework/core.py

"""
This module contains the high-level business logic that orchestrates the data pipeline.
It depends on the abstract interfaces defined in interfaces.py,
not on any concrete implementations.
"""

from my_framework.interfaces import IDataSource, IProcessor, IDataSink
from my_framework.utils import logger # Assuming a logger is defined in utils

class DataPipeline:
    """
    Orchestrates a data processing pipeline using a data source,
    a processor, and a data sink.
    """
    def __init__(self, data_source: IDataSource, processor: IProcessor, data_sink: IDataSink):
        """
        Initializes the pipeline with concrete implementations of the interfaces.
        """
        self.data_source = data_source
        self.processor = processor
        self.data_sink = data_sink

    def run(self):
        """
        Executes the full pipeline: extract, transform, load.
        """
        logger.info("Starting data pipeline execution...")

        # 1. Extract data from the source
        raw_data = self.data_source.get_data()
        logger.info("Data extracted successfully.")

        # 2. Transform the data
        processed_data = self.processor.process_data(raw_data)
        logger.info("Data transformed successfully.")

        # 3. Load the processed data to the sink
        self.data_sink.load_data(processed_data)
        logger.info("Data loaded successfully. Pipeline complete.")