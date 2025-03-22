from locust import HttpUser, task, between

class Layer7Attacker(HttpUser):
    wait_time = between(0.1, 0.5)  # Simulate real users

    @task
    def flood(self):
        self.client.get("/")  # Target homepage
        self.client.post("/api", json={"query": "test"})  # Target API
