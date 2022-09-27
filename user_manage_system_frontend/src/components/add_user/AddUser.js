import React, {useState} from "react";
import axios from "axios";
import Container from 'react-bootstrap/Container';
import {BASE_URL} from "../../utils/utils";
import "./AddUser.css";
import {useNavigate} from "react-router-dom";

const AddUser = () => {
    const [formValue, setFormValue] = React.useState({
        username: "",
        email: "",
        password: "",
        confirm_password: ""
    });

    const navigate = useNavigate()

    const handleSubmit = async (event) => {
        event.preventDefault()
        const keyArray = ["input_username", "input_email", "input_password", "input_confirm_password"]
        for (const currentKey of keyArray) {
            let currentElement = document.querySelector(`[name='${currentKey}']`);
            let currentErrorMessage = currentElement.parentElement.querySelector("p");
            currentElement.classList.remove("add-user_validation_error");
            currentErrorMessage.classList.remove("error_message_shown");
        }
        console.log(JSON.stringify(formValue))

        const formData = new FormData()
        formData.append("username", formValue.username)
        formData.append("email", formValue.email)
        formData.append("password", formValue.password)
        formData.append("confirm_password", formValue.confirm_password)

        await axios({
            method: "post",
            url: BASE_URL + "/users/",
            data: formData
        }).then(response => {
            navigate("/users/")
        }).catch(error => {
            const errors = error.response.data
            console.log(errors)
            for (const currentKey of Object.keys(errors)) {
                setError(currentKey, errors[currentKey])
            }
            window.scrollTo(0, 0)
        });
    }

    const setError = (key, error_message) => {
        key = "input_"+ key;
        let currentElement = document.querySelector(`[name='${key}']`);
        let currentErrorMessage = currentElement.parentElement.querySelector("p");
        currentElement.classList.add("add-user_validation_error");
        currentErrorMessage.classList.add("error_message_shown");
        currentErrorMessage.innerText = error_message;
    }

    const handleChange = (event) => {
        setFormValue({
            ...formValue,
            [event.target.name.replace("input_", "")]: event.target.value
        });
    }

    return (
        <Container fluid={true}>
            <form onSubmit={handleSubmit} className="add-user_form">
                <div className="add-user_wrapper">
                    <div className="add-user_midline_block">
                        <hr/>
                        <div className="add-user_midline_header_block">
                            <h1 className="add-user_midline_header">Create user</h1>
                        </div>
                        <hr/>
                    </div>
                    <div className="add-user_form_section">
                        <div className="add-user_form_section_wrapper">
                            <div className="add-user_form_item">
                                <p className="add-user_form_error_message">Error message</p>
                                <input
                                    type="text"
                                    name="input_username"
                                    className="add-user_form__input"
                                    placeholder={"Username"}
                                    value={formValue.username}
                                    onChange={handleChange}
                                />
                            </div>
                            <div className="add-user_form_item">
                                <p className="add-user_form_error_message">Error message</p>
                                <input
                                    type="text"
                                    name="input_email"
                                    className="add-user_form__input"
                                    placeholder={"Email"}
                                    value={formValue.email}
                                    onChange={handleChange}
                                />
                            </div>
                            <div className="add-user_form_item">
                                <p className="add-user_form_error_message">Error message</p>
                                <input
                                    type="password"
                                    name="input_password"
                                    className="add-user_form__input"
                                    placeholder={"Password"}
                                    value={formValue.password}
                                    onChange={handleChange}
                                />
                            </div>
                            <div className="add-user_form_item">
                                <p className="add-user_form_error_message">Error message</p>
                                <input
                                    type="password"
                                    name="input_confirm_password"
                                    className="add-user_form__input"
                                    placeholder={"Confirm password"}
                                    value={formValue.confirm_password}
                                    onChange={handleChange}
                                />
                            </div>



                        </div>
                        <hr/>
                        <div className="add-user_form_section">
                            <div className="add-user_submit_button_block">
                                <button type="submit"
                                        className="add-user_form__input__button"
                                >Submit
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
            </form>
        </Container>
)

}

export default AddUser;