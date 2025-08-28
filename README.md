# AWS Well-Architected Framework Review (WAFR) with Generative AI

This repository demonstrates a POC for accelerating AWS WAFR using Generative AI.

**Base repository:** [AWS WAFR With Gen AI](https://github.com/aws-samples/sample-well-architected-acceleration-with-generative-ai)

## Changes Made

- Updated model from **Claude 3.5** to **DeepSeek R1**
- Modified in:
  - [`2_Existing_WAFR_Reviews.py`](https://github.com/aws-samples/sample-well-architected-acceleration-with-generative-ai/blob/7ac3b7659d99d780b917026021ccafbabf4ac3ef/ui_code/tokenized-pages/2_Existing_WAFR_Reviews.py#L30) (once)
  - [`wafr_genai_accelerator_stack.py`](https://github.com/aws-samples/sample-well-architected-acceleration-with-generative-ai/blob/7ac3b7659d99d780b917026021ccafbabf4ac3ef/wafr_genai_accelerator/wafr_genai_accelerator_stack.py#L411) (four times)

## Prerequisites Installation

Execute these commands after activating the virtual environment (`. .venv/bin/activate`) and before running `cdk bootstrap`:

```bash
# Install required packages
sudo yum install pip git docker -y

# Install Node.js (required for AWS CDK)
curl -fsSL https://rpm.nodesource.com/setup_22.x | sudo bash -
sudo yum install -y nodejs

# Install AWS CDK globally
npm install -g aws-cdk

# Configure Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Add current user to docker group (requires re-login or newgrp to take effect)
sudo usermod -a -G docker $USER
newgrp docker

# Verify Docker is running
sudo systemctl status docker
```

## Setup Instructions

1. Clone this repository
2. Create and activate virtual environment:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate  # On Linux/Mac
   # or
   .venv\Scripts\activate     # On Windows
   ```
3. Run the prerequisite installation commands above
4. Bootstrap CDK:
   ```bash
   cdk bootstrap
   ```
5. Deploy the stack:
   ```bash
   cdk deploy
   ```
