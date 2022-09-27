import React, {useEffect} from "react";
import {Container} from "react-bootstrap";
import axios from "axios";
import {BASE_URL} from "../../utils/utils";
import {useNavigate} from "react-router-dom";

import "./UsersList.css"

const Block_users = (props) => {

    const navigate = useNavigate();

    const handlerNavigatorEditAccount = () => {
        navigate("/edit_user/" + props.id)
    }

    const handlerNavigatorUsersList = () => {
        navigate("/users/")
    }

    const DeleteAnAccount = () => {
        axios({
            method: "DELETE",
            url: BASE_URL + '/user/' + props.id + "/"
        })
            .then((response) => {
                console.log("bvdjzkfvbkjzdbrgvk")
                handlerNavigatorUsersList()
                window.location.reload()
            })
            .catch((error) => {
                if (error.response) {
                    console.log(error.response);
                    console.log(error.response.status);
                    console.log(error.response.headers);
                }
            })
    }

    return (

        <tr>
            <td>{props.id}</td>
            <td>{props.username}</td>
            <td>{props.email}</td>
            <td>{props.created_at}</td>
            <td>{props.groups}</td>
            <td><input type="checkbox" id={props.username} name={props.username} checked={props.is_admin} disabled={true}></input></td>
            <td className="user-list_actions_block">
                <div className="user-list_edit">
                    <p onClick={handlerNavigatorEditAccount}>
                        Edit
                    </p>
                </div>
                <div className="user-list_delete">
                    <p onClick={DeleteAnAccount}>
                        Delete
                    </p>
                </div>
            </td>
        </tr>

    );
}

const UsersList = () => {
    const [users, setUsers] = React.useState([]);
    useEffect(() => {
        getUsers();
    }, []);

    function getUsers() {
        axios.get(BASE_URL + "/users/")
            .then((response) => {
                const data = response.data
                setUsers(data)
            })
            .catch((error) => {
                if (error.response) {
                    console.log(error.response);
                    console.log(error.response.status);
                    console.log(error.response.headers);
                }
            })
    }


    const getAll = () => {
        let result = []
        let count = 0

        for (const user of Object.values(users)) {
            console.log(user)
            result.push(<Block_users key={count}
                                     username={user.username}
                                     email={user.email}
                                     created_at={new Date(user.created_at).toISOString().slice(0, 10)}
                                     groups={user.custom_group.length}
                                     id={user.id}
                                     is_admin={user.is_admin}
            />)
            count++
        }
        return result
    }

    const navigate = useNavigate();

    const handlerNavigatorAddAccount = () => {
        navigate("/add_user")
    }

    return (
        <Container fluid={true}>
            <div className="user-list_whole_page">
                <div className="user-list_header">
                    <div className="user-list_block_title">
                        <h1>All Users</h1>
                    </div>
                </div>
                <div className="user-list_list_of_all">
                    {
                        users.length === 0 ?
                            (<div className="user-list_no_users">
                                <p>
                                    There are no users here. You can register your first
                                    <b>
                                        <div className="user-list_add">
                                            <p onClick={handlerNavigatorAddAccount}>
                                                one
                                            </p>
                                        </div>
                                        here</b>.
                                </p>
                            </div>)
                            :
                            (
                                <div className="user-list_main_component">
                                    <div className="user-list_add">
                                        <p onClick={handlerNavigatorAddAccount}>
                                            Add user
                                        </p>
                                    </div>
                                    <table className="user-list_table">
                                        <thead>
                                        <tr>
                                            <th>№</th>
                                            <th>Username</th>
                                            <th>Email</th>
                                            <th>Created at</th>
                                            <th>Amount of groups</th>
                                            <th>Is Admin</th>
                                            <th>Actions</th>
                                        </tr>
                                        </thead>
                                        <tbody>
                                        {
                                            getAll()
                                        }
                                        </tbody>

                                    </table>
                                </div>
                            )
                    }
                </div>
            </div>
        </Container>
    )
}


export default UsersList;