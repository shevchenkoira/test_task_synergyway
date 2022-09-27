import React, {useCallback, useState, useEffect} from "react";
import Container from 'react-bootstrap/Container';
import {BASE_URL} from "../../utils/utils";
import axios from "axios";
import "./EditGroup.css";

import {useNavigate, useParams} from "react-router-dom";

const EditGroup = () => {
    const [groupInfo, setUserInfo] = React.useState({
        name: "",
        description: "",
    });

    const [formValue, setFormValue] = React.useState({
        name: "",
        description: "",
    });

    const navigate = useNavigate()

    const handleSubmit = async (event) => {
        event.preventDefault()

        for (const key of Object.keys(formValue)) {
            formValue[key] = groupInfo[key]
        }

        const keyArray = ["input_name", "input_description"]
        for (const currentKey of keyArray) {
            let currentElement = document.querySelector(`[name='${currentKey}']`);
            let currentErrorMessage = currentElement.parentElement.querySelector("p");
            currentElement.classList.remove("edit-group_validation_error");
            currentErrorMessage.classList.remove("error_message_shown");
        }

        const formData = new FormData()
        formData.append("name", formValue.name)
        formData.append("description", formValue.description)

        await axios({
            method: "patch",
            url: BASE_URL + "/group/" + id + "/",
            data: formData
        }).then(response => {
            navigate("/groups/")
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
        currentElement.classList.add("edit-group_validation_error");
        currentErrorMessage.classList.add("error_message_shown");
        currentErrorMessage.innerText = error_message;
    }

    const {id} = useParams()

    const getUserInfo = useCallback(
        async () => {
            await axios({
                method: "get",
                url: BASE_URL + "/group/" + id + "/",
            }).then(response => {
                setUserInfo(response.data)
            }).catch(err => {
                console.log(err)
            })
        }, []
    );

    const handleChange = (event) => {
        setUserInfo({
            ...groupInfo,
            [event.target.name.replace("input_", "")]: event.target.value
        });
    }

    useEffect(() => {
        getUserInfo();
    }, [getUserInfo])

    return (
        <Container fluid={true}>
            <form onSubmit={handleSubmit} className="edit-group_form">
                <div className="edit-group_wrapper">
                    <div className="edit-group_midline_block">
                        <hr/>
                        <div className="edit-group_midline_header_block">
                            <h1 className="edit-group_midline_header">Edit group</h1>
                        </div>
                        <hr/>
                    </div>
                    <div className="edit-group_form_section">
                        <div className="edit-group_form_section_wrapper">
                            <div className="edit-group_form_item">
                                <p className="edit-group_form_error_message">Error message</p>
                                <input
                                    type="text"
                                    name="input_name"
                                    className="edit-group_form__input"
                                    placeholder={"Name"}
                                    value={groupInfo.name}
                                    onChange={handleChange}
                                />
                            </div>
                            <div className="edit-group_form_item">
                                <p className="edit-group_form_error_message">Error message</p>
                                <input
                                    type="text"
                                    name="input_description"
                                    className="edit-group_form__input"
                                    placeholder={"Description"}
                                    value={groupInfo.description}
                                    onChange={handleChange}
                                />
                            </div>
                        </div>
                    </div>
                </div>

                <hr/>
                <div className="edit-group_form_section">
                    <div className="edit-group_submit_button_block">
                        <button type="submit"
                                className="edit-group_form__input__button"
                        >Submit
                        </button>
                    </div>
                </div>
        </form>
</Container>
)

}

export default EditGroup;