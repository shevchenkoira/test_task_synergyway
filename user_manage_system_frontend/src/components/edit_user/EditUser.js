import React, {useCallback, useState, useEffect} from "react";
import Container from 'react-bootstrap/Container';
import {BASE_URL} from "../../utils/utils";
import axios from "axios";
import "./EditUser.css";

import {useNavigate, useParams} from "react-router-dom";

const EditUser = () => {
    const [userInfo, setUserInfo] = React.useState({
        username: "",
        email: "",
        password: "",
        confirm_password: ""
    });

    const [formValue, setFormValue] = React.useState({
        username: "",
        email: "",
        password: "",
        confirm_password: ""
    });

    const navigate = useNavigate()

    const handleSubmit = async (event) => {
        event.preventDefault()

        for (const key of Object.keys(formValue)) {
            formValue[key] = userInfo[key]
        }

        const keyArray = ["input_username", "input_email", "input_password", "input_confirm_password"]
        for (const currentKey of keyArray) {
            let currentElement = document.querySelector(`[name='${currentKey}']`);
            let currentErrorMessage = currentElement.parentElement.querySelector("p");
            currentElement.classList.remove("add-user_validation_error");
            currentErrorMessage.classList.remove("error_message_shown");
        }

        const formData = new FormData()
        formData.append("username", formValue.username)
        formData.append("email", formValue.email)
        formData.append("password", formValue.password)
        formData.append("confirm_password", formValue.confirm_password)

        await axios({
            method: "patch",
            url: BASE_URL + "/user/" + id + "/",
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
        key = "input_" + key;
        let currentElement = document.querySelector(`[name='${key}']`);
        let currentErrorMessage = currentElement.parentElement.querySelector("p");
        currentElement.classList.add("edit-user_validation_error");
        currentErrorMessage.classList.add("error_message_shown");
        currentErrorMessage.innerText = error_message;
    }

    const {id} = useParams()

    const getUserInfo = useCallback(
        async () => {
            await axios({
                method: "get",
                url: BASE_URL + "/user/" + id + "/",
            }).then(response => {
                setUserInfo(response.data)
            }).catch(err => {
                console.log(err)
            })
        }, []
    );

    const handleChange = (event) => {
        setUserInfo({
            ...userInfo,
            [event.target.name.replace("input_", "")]: event.target.value
        });
    }

    useEffect(() => {
        getUserInfo();
    }, [getUserInfo])

    return (
        <Container fluid={true}>
            <form onSubmit={handleSubmit} className="edit-user_form">
                <div className="edit-user_wrapper">
                    <div className="edit-user_midline_block">
                        <hr/>
                        <div className="edit-user_midline_header_block">
                            <h1 className="edit-user_midline_header">Edit user</h1>
                        </div>
                        <hr/>
                    </div>
                    <div className="edit-user_form_section">
                        <div className="edit-user_form_section_wrapper">
                            <div className="edit-user_form_item">
                                <p className="edit-user_form_error_message">Error message</p>
                                <input
                                    type="text"
                                    name="input_username"
                                    className="edit-user_form__input"
                                    placeholder={"Username"}
                                    value={userInfo.username}
                                    onChange={handleChange}
                                />
                            </div>
                            <div className="edit-user_form_item">
                                <p className="edit-user_form_error_message">Error message</p>
                                <input
                                    type="text"
                                    name="input_email"
                                    className="edit-user_form__input"
                                    placeholder={"Email"}
                                    value={userInfo.email}
                                    onChange={handleChange}
                                />
                            </div>
                            <div className="edit-user_form_item">
                                <p className="edit-user_form_error_message">Error message</p>
                                <input
                                    type="password"
                                    name="input_password"
                                    className="edit-user_form__input"
                                    placeholder={"Password"}
                                    value={userInfo.password}
                                    onChange={handleChange}
                                />
                            </div>
                            <div className="edit-user_form_item">
                                <p className="edit-user_form_error_message">Error message</p>
                                <input
                                    type="password"
                                    name="input_confirm_password"
                                    className="edit-user_form__input"
                                    placeholder={"Confirm password"}
                                    value={userInfo.confirm_password}
                                    onChange={handleChange}
                                />
                            </div>
                        </div>
                    </div>
                </div>

                <hr/>
                <div className="edit-user_form_section">
                    <div className="edit-user_submit_button_block">
                        <button type="submit"
                                className="edit-user_form__input__button"
                        >Submit
                        </button>
                    </div>
                </div>
        </form>
</Container>
)

}

export default EditUser;