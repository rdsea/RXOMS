# SOARML
Explainable Model for Orchestrating ML-based Security Tool for Digital Twin

There is a big growth in using Digital Twins to monitor and optimize systems in the (Industrial) IoT environment (IIoT) or in the digital society in general. 
On the other hand, because security is of paramount importance, such systems may employ many security tools/frameworks, which increasingly adopt machine learning (ML) to automate threat detection and mitigate the consequences. 
It poses new challenges in tool unification (from multi-vendors, data formats) and explainability in security orchestration and response. 
In this study, we want to build an explainable orchestration model by abstracting security reports, including ML-specific attributes, working with different security tools, and providing sufficient information for performance evaluation (by humans in the loop) with less effort. 
Moreover, standardizing security reports and security plans will encourage the security playbook development and integration with ML-based orchestration (continuous learning) and the digital twin's knowledge graph for automating security configuration.

# Requirement
- Mininet
- Ryu
- QoA4ML
- Numpy
- Pandas

# Experiment
Start Ryu Controller: 
- Navigate to `controller` folder
```bash
$ ryu-manager ryuRestFirewall.py
```

- Enable filewall on all switch
