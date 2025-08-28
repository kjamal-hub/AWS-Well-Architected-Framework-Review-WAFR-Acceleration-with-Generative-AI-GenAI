# AWS Well-Architected Framework Review (WAFR) with Generative AI

This repo demonstrates a POC for accelerating AWS WAFR using Generative AI.  
Base repo: [AWS WAFR With Gen Ai](https://github.com/aws-samples/sample-well-architected-acceleration-with-generative-ai)

### Changes Made
- Updated model from **Claude 3.5** to **DeepSeek R1**  
- Modified in:
  - [`2_Existing_WAFR_Reviews.py`](https://github.com/aws-samples/sample-well-architected-acceleration-with-generative-ai/blob/7ac3b7659d99d780b917026021ccafbabf4ac3ef/ui_code/tokenized-pages/2_Existing_WAFR_Reviews.py#L30) (once)  
  - [`wafr_genai_accelerator_stack.py`](https://github.com/aws-samples/sample-well-architected-acceleration-with-generative-ai/blob/7ac3b7659d99d780b917026021ccafbabf4ac3ef/wafr_genai_accelerator/wafr_genai_accelerator_stack.py#L411) (four times)


after `activation .venv` & before `cdk bootstrap`

> yum install pip git docker -y
> curl -fsSL https://rpm.nodesource.com/setup_22.x | sudo bash -
> sudo yum install -y nsolid
> npm install -g aws-cdk
> sudo systemctl start docker
> sudo systemctl enable docker
> sudo usermod -a -G docker ec2-user
> newgrp docker
> sudo systemctl status docker
