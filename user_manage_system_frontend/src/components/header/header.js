import React from "react";
import {BASE_URL} from "../../utils/utils";
import "./header.css"

export default function Header() {
    return (
        <header className="header sticky sticky--top js-header">
            <nav className="navigation">
                <ul className="navigation__list navigation__list--inline">
                    <li className="navigation__item"><a href={"/users/"}
                                                        className="navigation__link">Users</a></li>
                    <li className="navigation__item"><a href={"/groups/"}
                                                        className="navigation__link">Groups</a></li>
                </ul>
            </nav>
        </header>
    );
}
