import pytest
from pyspark.sql import SparkSession


@pytest.fixture(scope="session")
def spark():
    """
    Real Spark, real local[2] execution engine - not a mock. Only the
    Kafka *source* needs a live broker (untestable here); this fixture
    proves the transformation logic actually runs under Spark.
    """
    session = (
        SparkSession.builder
        .master("local[2]")
        .appName("cyberstream-streaming-tests")
        .config("spark.sql.shuffle.partitions", "2")
        .config("spark.ui.enabled", "false")
        .getOrCreate()
    )
    session.sparkContext.setLogLevel("WARN")
    yield session
    session.stop()
