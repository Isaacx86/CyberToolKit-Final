from locust import HttpUser, task, between

class MyUser(HttpUser):
    wait_time = between(1, 5)

    @task
    def view_home_page(self):
        self.client.get("/")

    @task
    def register_user(self):
        self.client.get("/register")

    @task
    def login_user(self):
        self.client.get("/login")


    @task
    def login(self):
        # Define the login payload (username and password)
        payload = {
            'username': 'admin',
            'password': 'password'
        }

        # Send a POST request to the login endpoint
        response = self.client.post("/login", json=payload)

        # Print the response status code and content
        print(f"Login Status Code: {response.status_code}")
        print(f"Login Response Content: {response.content}")



if __name__ == "__main__":
    import sys
    from locust import main

    sys.argv = ["-f", __file__, "--host", "http://localhost:5000"]
    main()
