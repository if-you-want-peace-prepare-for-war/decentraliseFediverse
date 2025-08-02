#!/bin/bash

# Define the environment name and required Python version
ENV_NAME="domain_analysis"
REQUIRED_PYTHON_VERSION="3.12"

# Check if the conda environment exists
if conda info --envs | grep -q "$ENV_NAME"; then
    # Get the current Python version in the environment
    CURRENT_PYTHON_VERSION=$(conda run -n $ENV_NAME python --version 2>&1 | awk '{print $2}' | cut -d '.' -f 1-2)

    # Compare the current Python version with the required version
    if [ "$CURRENT_PYTHON_VERSION" != "$REQUIRED_PYTHON_VERSION" ]; then
        echo "Updating environment '$ENV_NAME' to Python $REQUIRED_PYTHON_VERSION..."
        conda activate $ENV_NAME
        conda install python=$REQUIRED_PYTHON_VERSION -y
    else
        echo "Environment '$ENV_NAME' already exists with the correct Python version ($CURRENT_PYTHON_VERSION)."
    fi
else
    # Create the environment if it does not exist
    echo "Creating environment '$ENV_NAME' with Python $REQUIRED_PYTHON_VERSION..."
    conda create -n $ENV_NAME python=$REQUIRED_PYTHON_VERSION -y
    conda activate $ENV_NAME
fi

# Install required packages
echo "Installing required packages from requirements.txt..."
pip install -r requirements.txt
